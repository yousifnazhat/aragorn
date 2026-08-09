"""Verify the bounded P3.7c worker activation and expiry observation."""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from datetime import timedelta
from decimal import Decimal
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import runtime_action_broker as broker
from . import runtime_action_broker_v4 as broker_v4
from . import runtime_action_decision as action_decision
from . import runtime_action_worker_openclaw_systemd_evidence as parent_verifier
from .admission_evidence import AdmissionEvidenceError, _time
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_broker import RuntimeActionBrokerError
from .runtime_active_skill_lineage import parse_active_runtime_record
from .runtime_capability_grant import parse_runtime_capability_grant
from .runtime_process_profile import runtime_process_profile

_SCHEMA = "aragorn/runtime-action-worker-activation-expiry-systemd-observation/v1"
_AUTHORITY = (
    "BOUNDED_ACTIVATION_EXPIRY_ROTATION_OBSERVATION_ONLY_"
    "NOT_VERIFIED_RUN_EDR_INSTALLER_RELEASE_AUTHORITY"
)
_EVIDENCE_BYTES = 311_385
_EVIDENCE_RAW_DIGEST = (
    "sha256:b9d360c7b5b7eac5e66f79a4a2b09b70094070bc297619f499ac880663d8ad91"
)
_EVIDENCE_DIGEST = (
    "sha256:a0607801571db26cf8d2f2c07ebc6ca7675da8dbc2f385e0e64f5ab5e3187322"
)
_RETAINED_PATH = (
    "benchmark/evidence/runtime-action-worker-activation-expiry-systemd-"
    "composition-p3-7c-2026-08-09.json"
)
_PARENT_RECEIPT_BYTES = 5_147
_PARENT_RECEIPT_RAW_DIGEST = (
    "sha256:154edc574bf00bd590c77de67b32764c5ecaf8a5582092487c6aa01bd23e4eb3"
)
_PARENT_RECEIPT_DIGEST = (
    "sha256:a920f71e196db07b4c8aa6838e23473bd8dc5d245368c5e6285484a4d4e8fd02"
)
_PARENT_VERIFIER_DIGEST = (
    "sha256:68b240d19ca5625d027f5ed21520bc8a10a02a16b6c0c96908c1741b6b943812"
)
_PARENT_RECEIPT_PATH = (
    "benchmark/receipts/phase3-runtime-action-worker-openclaw-systemd-"
    "qualification-v1-2026-08-09.json"
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HARNESS_DIGEST = (
    "sha256:65d7fdbed1367c3aaac90c08afd89a6b10c1d40fbf90313a67761a0335cb5716"
)
_IMAGE_LINEAGE_DIGEST = (
    "sha256:3d82195d79fcfd2da527e3a6fbe0acb20bb8860c1f8909a27c093199dfc41c6b"
)
_INSTALLED_CLOSURE_DIGEST = (
    "sha256:ca589661cd02bb069a4c1c9919469ebe1c97148a7f392f1b4317841a0e7ecc57"
)
_SOURCE_CLOSURE_DIGEST = (
    "sha256:18f5c274ec548a0b7b23fd5523755a0a2087e7346c1dc51a62892a5b879d675b"
)
_PAIR_CLOSURE_DIGEST = (
    "sha256:8226b5760bba3025d7d15259a4091af6aef190921a61194502ea157a9ba644df"
)
_OBSOLETE_SHIMS_DIGEST = (
    "sha256:2d75717637e4f734db3a5ec59d153f106fa80989e445b0f963374cd697d6bb6e"
)
_COLLECTOR_DIGEST = (
    "sha256:be7a6553d092778a8ca61a7be72c667673fa737d12b7a6ffe86a5835182e4c49"
)
_SOURCE_COMMIT = "a6a8a8be8f868f3107adafa7c9ca5a51a7ce2044"
_PARENT_IMAGE = (
    "sha256:1afab032375efbe87ac938c0993880e164d6dace2e37239a27c6def8e320e1db"
)
_CHILD_IMAGE = "sha256:3c8321a7118684b8358876179406da6f12fb814dcfc3a1731a923c8bb5b3fe07"
_RECORDED_AT = "2026-08-09T18:38:56.247311Z"
_TOP_LEVEL = {
    "artifacts",
    "authority",
    "boundaries",
    "cases",
    "decision",
    "harness",
    "identities",
    "inputs",
    "limitations",
    "parent",
    "profiles",
    "recorded_at",
    "runtime",
    "schema",
    "secret_checks",
}
_LIMITATIONS = [
    "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "EXACT_OPENCLAW_2026_7_1_RUNTIME_VOLUME_AND_EVALUATOR_PROVIDER_ONLY",
    "ONE_AVAILABLE_TO_EXPIRED_TRANSITION_ONLY",
    "ONE_OPERATOR_UNMASK_AND_TERMINAL_ARCHIVE_ROTATION_ONLY",
    "ONE_FRESH_GRANT_AND_ONE_CREATE_ACTION_ONLY",
    "EXPIRY_USES_LOCAL_WALL_CLOCK_WITHOUT_EXTERNAL_TIME_ATTESTATION",
    "NO_CLOCK_STEP_SLEW_ROLLBACK_OR_EXPIRY_LATENCY_QUALIFICATION",
    "NO_REBOOT_SYSTEMD_REEXEC_BOOT_ACTIVATION_OR_CREDENTIAL_REPROJECTION",
    "NO_SIGKILL_POWER_LOSS_OR_FILESYSTEM_DURABILITY_FAULT_INJECTION",
    "NO_AUTOMATIC_CONTINUOUS_REPEATED_OR_OVERLAPPING_GRANT_RENEWAL",
    "NO_CONCURRENT_ACTIVATION_LOCK_CONTENTION_OR_PARTIAL_SYSTEMCTL_FAILURE",
    "NO_CLAIMED_CONNECTION_ACROSS_EXPIRY_QUALIFICATION",
    "NO_NATIVE_HOST_VM_HOSTILE_ROOT_OR_SAME_UID_DIRECTORY_ATTESTATION",
    "SOURCE_COMMIT_SIGNATURE_TRUSTS_LOCAL_GIT_CONFIGURATION_AND_KEYRING",
    "CONTAINER_BUILD_AND_CAPTURE_TOOLCHAIN_NOT_INDEPENDENTLY_ATTESTED",
    "PYTHON_NODE_SYSTEMD_KERNEL_AND_NATIVE_DEPENDENCY_CLOSURE_NOT_FULLY_PINNED",
    "PROVIDER_AND_OPENCLAW_SESSION_RAW_BYTES_NOT_RETAINED",
    "P3_7B_PARENT_REMAINS_SEPARATE_IMMUTABLE_QUALIFICATION",
    "SYSCALL_CAUSATION_IS_PINNED_IMPLEMENTATION_BOUND_NOT_INDEPENDENT_ATTESTATION",
    "TRACE_PROVES_ONE_ROUTE_CONNECT_WITHOUT_RETRY_NOT_APPLICATION_SEND_COUNT",
    "VERIFIER_NOT_IMPLEMENTED",
    "RETAINED_EVIDENCE_NOT_PRODUCED",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "INSTALLER_AUTHORITY_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_DECISION = {
    "aggregate_gate_eligible": False,
    "available_to_expired_observed": True,
    "coherent_allow_created_consumed_observed": True,
    "edr_claim_eligible": False,
    "expired_activation_fail_stop_observed": True,
    "full_activation_no_boot_authority_observed": True,
    "installer_authority_eligible": False,
    "parent_p3_7b_unchanged": True,
    "phase3_exit_eligible": False,
    "public_release_eligible": False,
    "retained_evidence_eligible": False,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "status": "P3_7C_ACTIVATION_EXPIRY_OBSERVED",
    "terminal_archive_rotation_observed": True,
    "verifier_status": "NOT_TESTED",
}
_QUALIFICATION_LIMITATIONS = [
    value
    for value in _LIMITATIONS
    if value not in {"VERIFIER_NOT_IMPLEMENTED", "RETAINED_EVIDENCE_NOT_PRODUCED"}
]
_QUALIFICATION_LIMITATIONS.insert(
    20, "PYTHON_STDLIB_AND_DYNAMIC_VERIFIER_DEPENDENCY_CLOSURE_NOT_PINNED"
)
_QUALIFICATION_DECISION = {
    "aggregate_gate_eligible": False,
    "bounded_activation_expiry_evidence_eligible": True,
    "edr_claim_eligible": False,
    "installer_authority_eligible": False,
    "parent_p3_7b_unchanged": True,
    "phase3_exit_eligible": False,
    "public_release_eligible": False,
    "qualified_pair_retained_evidence_eligible": True,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "source_observation_unchanged": True,
    "source_observation_verified": True,
    "status": "P3_7C_BOUNDED_PASS",
}


def verify_runtime_action_worker_activation_expiry_systemd_evidence(
    document: Mapping[str, Any],
    parent_observation: Mapping[str, Any],
    parent_parent: Mapping[str, Any],
    parent_receipt: Mapping[str, Any],
    *,
    expected_digest: str | None,
) -> None:
    """Replay the exact P3.7c artifact without promoting broader authority."""

    try:
        _expect(expected_digest == _EVIDENCE_DIGEST, "retained digest pin changed")
        _expect(set(document) == _TOP_LEVEL, "top-level fields changed")
        _expect(not parent_verifier._contains_float(document), "float is invalid")
        encoded = canonical_json(document)
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
        parent_verifier.verify_runtime_action_worker_openclaw_systemd_evidence(
            parent_observation,
            parent_parent,
            expected_digest=parent_verifier._EVIDENCE_DIGEST,
        )
        expected_parent_receipt = (
            parent_verifier.runtime_action_worker_openclaw_systemd_qualification(
                parent_observation,
                parent_parent,
                expected_digest=parent_verifier._EVIDENCE_DIGEST,
                implementation_digest=_PARENT_VERIFIER_DIGEST,
            )
        )
        receipt_encoded = canonical_json(parent_receipt)
        _expect(parent_receipt == expected_parent_receipt, "parent receipt changed")
        _expect(
            canonical_digest(parent_receipt) == _PARENT_RECEIPT_DIGEST
            and _raw_digest(receipt_encoded + b"\n") == _PARENT_RECEIPT_RAW_DIGEST
            and len(receipt_encoded) + 1 == _PARENT_RECEIPT_BYTES,
            "parent receipt identity changed",
        )
        _verify_parent(document["parent"])
        _verify_records(document)
        _verify_artifacts(document["artifacts"])
        _verify_harness(document["harness"])
        context = _verify_inputs(
            document["inputs"],
            document["profiles"],
            document["identities"],
            document["harness"]["document"]["container_id"],
        )
        _verify_cases(document["cases"], document["boundaries"], context)
        _verify_secrets(document["secret_checks"], document["cases"])
        _expect(document["runtime"] == parent_verifier._RUNTIME, "runtime changed")
        _expect(
            _time(document["recorded_at"])
            >= _time(
                document["cases"]["coherent_consumed"]["broker_journal_after"][
                    "completed_at"
                ]
            ),
            "source completion time changed",
        )
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
            f"invalid runtime worker activation expiry systemd evidence: {exc}"
        ) from exc


def runtime_action_worker_activation_expiry_systemd_qualification(
    document: Mapping[str, Any],
    parent_observation: Mapping[str, Any],
    parent_parent: Mapping[str, Any],
    parent_receipt: Mapping[str, Any],
    *,
    expected_digest: str | None,
    implementation_digest: str | None = None,
) -> dict[str, Any]:
    """Return the bounded deterministic P3.7c qualification."""

    verify_runtime_action_worker_activation_expiry_systemd_evidence(
        document,
        parent_observation,
        parent_parent,
        parent_receipt,
        expected_digest=expected_digest,
    )
    verifier_digest = _raw_digest(Path(__file__).read_bytes())
    _expect(
        implementation_digest is not None and implementation_digest == verifier_digest,
        "verifier implementation pin changed",
    )
    artifacts = document["artifacts"]
    harness = document["harness"]["document"]
    cases = document["cases"]
    return {
        "assurance": (
            "SEMANTICALLY_REPLAY_VERIFIED_PINNED_ACTIVATION_EXPIRY_ROTATION_"
            "AND_CONSUMED_ACTION_EVIDENCE"
        ),
        "bindings": {
            "activation": {
                "gateway_config_digest": canonical_digest(
                    document["inputs"]["gateway_config"]
                ),
                "lock_path": document["boundaries"]["activation_lock"],
                "unit_fragment_digests": {
                    name: unit["FragmentDigest"]
                    for name, unit in document["boundaries"]["units"].items()
                },
                "worker_binding_digest": canonical_digest(
                    document["inputs"]["worker_binding"]
                ),
            },
            "grants": {
                "expired_archive_digest": cases["terminal_archive_rotation"]["after"][
                    "archive"
                ]["digest"],
                "expired_state_digest": cases["expired_fail_stop"]["expiry"][
                    "expired_state"
                ]["digest"],
                "final_consumed_state_digest": cases["coherent_consumed"][
                    "grant_state"
                ]["digest"],
                "fresh_grant_digest": document["inputs"]["fresh_grant"]["digest"],
                "short_grant_digest": document["inputs"]["short_grant"]["digest"],
            },
            "harness": {
                "child_image_id": harness["image_id"],
                "harness_digest": document["harness"]["digest"],
                "image_lineage_digest": canonical_digest(harness["image_lineage"]),
                "parent_image_id": harness["parent_image_id"],
                "source_commit": harness["source_commit"],
            },
            "implementation": {
                "capture_recipe_digest": artifacts["collector"]["capture_recipe"][
                    "digest"
                ],
                "dockerfile_digest": artifacts["collector"]["dockerfile"]["digest"],
                "driver_digest": artifacts["collector"]["driver"]["digest"],
                "installed_closure_digest": artifacts["installed_closure_digest"],
                "probe_digest": artifacts["collector"]["probe"]["digest"],
                "verifier_implementation_digest": verifier_digest,
                "worker_installer_digest": artifacts["worker_installer"]["digest"],
            },
            "parent_qualification": {
                "observation": dict(document["parent"]["observation"]),
                "receipt": dict(document["parent"]["receipt"]),
                "schema_digest": document["parent"]["schema_digest"],
                "verifier_digest": document["parent"]["verifier_digest"],
            },
            "runtime": {
                "tree_digest": document["runtime"]["tree"]["tree_digest"],
                "version": document["runtime"]["expected_version"],
                "volume": harness["openclaw_runtime_volume"],
            },
            "source_observation": {
                "authority": _AUTHORITY,
                "bytes": _EVIDENCE_BYTES,
                "canonical_digest": _EVIDENCE_DIGEST,
                "path": _RETAINED_PATH,
                "raw_digest": _EVIDENCE_RAW_DIGEST,
                "schema": _SCHEMA,
            },
        },
        "cases": {
            "coherent_consumed": {
                "driver_status": "COMPLETED",
                "effect_status": "CREATED",
                "grant_state": "CONSUMED",
                "status": "PASS",
                "verdict": "ALLOW",
            },
            "expired_fail_stop": {
                "activation_exit_code": 1,
                "grant_state": "EXPIRED",
                "route_fail_stopped": True,
                "status": "PASS",
            },
            "full_activation": {
                "boot_authority": False,
                "service_state": "FOUR_ACTIVE",
                "status": "PASS",
            },
            "terminal_archive_rotation": {
                "archive_exact": True,
                "status": "PASS",
                "transition": "EXPIRED_TO_AVAILABLE",
            },
        },
        "decision": dict(_QUALIFICATION_DECISION),
        "limitations": list(_QUALIFICATION_LIMITATIONS),
        "schema": (
            "aragorn/runtime-action-worker-activation-expiry-systemd-qualification/v1"
        ),
        "source_recorded_at": document["recorded_at"],
    }


def _verify_inputs(
    inputs: Mapping[str, Any],
    profiles: Mapping[str, Any],
    identities: Mapping[str, Any],
    container_id: str,
) -> dict[str, Any]:
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
        "input inventory changed",
    )
    _expect(
        identities
        == {
            "broker": {"gid": 997, "uid": 995},
            "gateway": {"gid": 992, "uid": 992},
            "sensor": {"gid": 996, "uid": 996},
            "worker": {"gid": 997, "uid": 997},
        },
        "principal split changed",
    )
    action = inputs["action"]
    _expect(
        action
        == {
            "operation_digest": canonical_digest(
                {"operation": "create", "schema": "aragorn/runtime-file-operation/v1"}
            ),
            "path_digest": parent_verifier._ACTION_PATH_DIGEST,
            "payload_digest": _raw_digest(b"Aragorn P3.7b distinct worker create\n"),
        },
        "action binding changed",
    )
    producer = inputs["producer"]
    _expect(
        set(producer) == {"projected_skill", "record", "skill", "transaction"},
        "producer inventory changed",
    )
    record = producer["record"]
    transaction = producer["transaction"]
    parsed_record = parse_active_runtime_record(canonical_json(record["document"]))
    expected_version_path = (
        f".aragorn-versions/{transaction['destination']['target_name']}/"
        f"{transaction['context_id'][7:]}-{transaction['manifest_digest'][7:]}"
    )
    _expect(
        set(record) == {"digest", "document", "file", "raw_digest"}
        and parsed_record == record["document"]
        and parsed_record["transaction"] == transaction
        and record["digest"]
        == record["raw_digest"]
        == record["file"]["digest"]
        == canonical_digest(record["document"])
        and record["file"]["bytes"] == len(canonical_json(record["document"]))
        and record["file"]["path"]
        == "/var/lib/aragorn-protected/skills/.aragorn-active-runtime.json"
        and transaction["schema"] == "aragorn/protected-install-transaction/v1"
        and transaction["authority"]
        == "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
        and transaction["context_digest"]
        == "sha256:3609dd27896e468d976f5f0bfe7cb47f526ab8ff272c3bb9ec3a69ca9f6924ca"
        and transaction["operation"] == "install"
        and transaction["expected_active"] is None
        and transaction["destination"]
        == {
            "root_device": 83,
            "root_inode": 1_199_182,
            "target_name": "aragorn-admitted",
        }
        and transaction["version_path"] == expected_version_path,
        "producer lineage changed",
    )
    expected_skill_path = (
        f"/var/lib/aragorn-protected/skills/{expected_version_path}/SKILL.md"
    )
    _expect(
        producer["skill"]["path"] == expected_skill_path
        and producer["projected_skill"]["path"]
        == "/var/lib/aragorn-agent-gateway/state/skills/template-skill/SKILL.md"
        and producer["skill"]["digest"] == producer["projected_skill"]["digest"]
        and all(
            item["stat"]["type"] == "file"
            and item["stat"]["uid"] == item["stat"]["gid"] == 0
            and item["stat"]["mode"] == "0444"
            and item["stat"]["nlink"] == 1
            for item in (producer["skill"], producer["projected_skill"])
        ),
        "producer skill binding changed",
    )
    policy = inputs["policy"]
    _expect(
        inputs["policy_digest"] == canonical_digest(policy)
        and policy["schema"] == "aragorn/runtime-action-policy/v1"
        and policy["id"] == "p3-7c-worker-activation-expiry"
        and policy["sensor_digest"] == "sha256:" + "3" * 64
        and policy["revocation_source_digest"] == "sha256:" + "4" * 64
        and policy["default"] == "BLOCK"
        and policy["version"] == 1
        and policy["allow"]
        == [
            {
                **action,
                "active_skill_digest": producer["skill"]["digest"],
                "runtime_digest": parent_verifier._RUNTIME["tree"]["tree_digest"],
            }
        ],
        "worker policy changed",
    )
    action_decision._policy(policy)
    _expect(
        canonical_digest(inputs["gateway_config"])
        == "sha256:65e0fe737f7d094bf89d10ae5854e934ca734c8a4ea0479a6eb3b96335a8a006",
        "gateway configuration changed",
    )
    _verify_profiles(profiles, producer, container_id)
    grants: dict[str, Mapping[str, Any]] = {}
    for name in ("short_grant", "fresh_grant"):
        wrapper = inputs[name]
        expected_fields = (
            {"digest", "document", "source"}
            if name == "short_grant"
            else {"digest", "document"}
        )
        grant = parse_runtime_capability_grant(canonical_json(wrapper["document"]))
        _expect(
            set(wrapper) == expected_fields
            and wrapper["digest"] == canonical_digest(grant)
            and grant["runtime_profile_digest"] == profiles["worker"]["digest"]
            and grant["runtime_digest"]
            == parent_verifier._RUNTIME["tree"]["tree_digest"]
            and grant["active_skill_digest"] == producer["skill"]["digest"]
            and grant["sensor_digest"] == policy["sensor_digest"]
            and grant["policy_digest"] == inputs["policy_digest"]
            and grant["policy_version"] == policy["version"]
            and grant["operation_digest"] == action["operation_digest"]
            and grant["source_manifest_digest"] == transaction["manifest_digest"]
            and grant["install_context_digest"] == transaction["context_digest"],
            f"{name} binding changed",
        )
        grants[name] = {"digest": wrapper["digest"], "document": grant}
    short_source = inputs["short_grant"]["source"]
    final_source = inputs["grant_source"]
    _expect(
        _verify_document_snapshot(short_source) == grants["short_grant"]["document"]
        and short_source["digest"] == grants["short_grant"]["digest"]
        and _verify_document_snapshot(final_source) == grants["fresh_grant"]["document"]
        and final_source["digest"] == grants["fresh_grant"]["digest"]
        and short_source["file"]["path"]
        == final_source["file"]["path"]
        == "/etc/aragorn/runtime-capability-grant.json"
        and short_source["file"]["stat"]["mode"]
        == final_source["file"]["stat"]["mode"]
        == "0400"
        and all(
            source["file"]["stat"]["uid"] == source["file"]["stat"]["gid"] == 0
            and source["file"]["stat"]["nlink"] == 1
            for source in (short_source, final_source)
        )
        and grants["short_grant"]["digest"] != grants["fresh_grant"]["digest"]
        and grants["short_grant"]["document"]["grant_id"]
        != grants["fresh_grant"]["document"]["grant_id"],
        "grant source rotation changed",
    )
    binding = inputs["worker_binding"]
    _expect(
        binding
        == {
            "active_skill_digest": producer["skill"]["digest"],
            "policy_digest": inputs["policy_digest"],
            "policy_version": policy["version"],
            "runtime_digest": parent_verifier._RUNTIME["tree"]["tree_digest"],
            "schema": "aragorn/runtime-action-worker-binding/v1",
        }
        and inputs["worker_binding_file"]["path"]
        == "/etc/aragorn/runtime-action-worker.json"
        and inputs["worker_binding_file"]["digest"] == canonical_digest(binding)
        and inputs["worker_binding_file"]["bytes"] == len(canonical_json(binding))
        and inputs["worker_binding_file"]["stat"]["mode"] == "0400",
        "worker binding changed",
    )
    _verify_control_sets(
        inputs["control_sets"],
        policy,
        action,
        producer["skill"]["digest"],
        grants,
    )
    return {
        "action": action,
        "container_id": container_id,
        "control_sets": inputs["control_sets"],
        "fresh_grant": grants["fresh_grant"],
        "fresh_grant_source": final_source,
        "identities": identities,
        "policy": policy,
        "producer": producer,
        "profiles": profiles,
        "short_grant": grants["short_grant"],
        "short_grant_source": short_source,
    }


def _verify_profiles(
    profiles: Mapping[str, Any], producer: Mapping[str, Any], container_id: str
) -> None:
    _expect(set(profiles) == {"executables", "worker"}, "profiles changed")
    profile = profiles["worker"]
    parsed = runtime_process_profile(profile["document"])
    executables = profiles["executables"]
    expected = {
        "node": {
            "bytes": 121_333_752,
            "digest": "sha256:3a988781edde7f1c76751f771cf402e0866fb4a81fbcd0852a2ce2f5bd2ccd37",
            "path": "/usr/local/bin/node",
        },
        "worker_python": {
            "bytes": 67_608,
            "digest": "sha256:7863a4d5e03fde7791c7f8c2c304cf3522f435e19745364ad18a6b7a0458af57",
            "path": "/usr/local/bin/python3.12",
        },
    }
    _expect(
        set(profile) == {"digest", "document"}
        and parsed.digest == profile["digest"]
        and set(executables) == set(expected)
        and all(
            {field: record[field] for field in ("bytes", "digest", "path")}
            == expected[name]
            and record["stat"]["type"] == "file"
            and record["stat"]["uid"] == record["stat"]["gid"] == 0
            and record["stat"]["mode"] == "0755"
            and record["stat"]["nlink"] == 1
            for name, record in executables.items()
        )
        and profile["document"]["executable_digest"]
        == executables["worker_python"]["digest"]
        and profile["document"]["runtime_digest"]
        == parent_verifier._RUNTIME["tree"]["tree_digest"]
        and profile["document"]["skill_path"] == producer["skill"]["path"]
        and profile["document"]["cgroup"]
        == f"/docker/{container_id}/system.slice/{parent_verifier._WORKER_UNIT}",
        "worker profile changed",
    )


def _verify_control_sets(
    control_sets: Mapping[str, Any],
    policy: Mapping[str, Any],
    action: Mapping[str, Any],
    skill_digest: str,
    grants: Mapping[str, Mapping[str, Any]],
) -> None:
    counters = {"expiry": 1, "activation": 2, "coherent_refresh": 3}
    _expect(set(control_sets) == set(counters), "control epochs changed")
    prior = -1
    for name, counter in counters.items():
        controls = control_sets[name]
        _expect(
            set(controls) == {"health", "observation", "policy", "revocations", "state"}
            and controls["policy"] == policy,
            f"{name} control set changed",
        )
        action_decision._policy(controls["policy"])
        action_decision._revocations(controls["revocations"])
        action_decision._health(controls["health"])
        action_decision._active(controls["observation"]["active"])
        action_decision._measured_action(controls["observation"]["measured_action"])
        broker._state(controls["state"])
        observed = controls["observation"]["observed_at_unix"]
        _expect(
            broker._observation(controls["observation"], observed)
            == controls["observation"]
            and controls["observation"]["sequence"] == counter
            and controls["health"]["epoch"] == counter
            and controls["revocations"]["generation"] == counter
            and controls["health"]["observed_at_unix"]
            == controls["revocations"]["observed_at_unix"]
            == observed
            and controls["observation"]["expires_at_unix"] == observed + 5
            and controls["health"]["expires_at_unix"] == observed + 15
            and controls["revocations"]["expires_at_unix"] == observed + 15
            and observed > prior,
            f"{name} control timing changed",
        )
        active = controls["observation"]["active"]
        measured = controls["observation"]["measured_action"]
        _expect(
            controls["health"]["status"] == "healthy"
            and controls["health"]["runtime_digest"]
            == active["runtime_digest"]
            == measured["runtime_digest"]
            == parent_verifier._RUNTIME["tree"]["tree_digest"]
            and controls["health"]["sensor_digest"]
            == controls["observation"]["sensor_digest"]
            == policy["sensor_digest"]
            and controls["revocations"]["source_digest"]
            == policy["revocation_source_digest"]
            and controls["revocations"]["skill_digests"] == []
            and active["active_skill_digest"]
            == measured["active_skill_digest"]
            == skill_digest
            and {
                field: active[field]
                for field in ("run_id", "session_id", "tool_call_id")
            }
            == {
                field: measured[field]
                for field in ("run_id", "session_id", "tool_call_id")
            }
            and all(measured[field] == action[field] for field in action)
            and controls["state"]
            == {
                "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
                "consumed": [],
                "effect_journal": None,
                "minimum_mediator_health_epoch": 1,
                "minimum_revocation_generation": 1,
                "schema": "aragorn/runtime-action-broker-state/v2",
            },
            f"{name} control authority changed",
        )
        grant = grants["short_grant" if name == "expiry" else "fresh_grant"]["document"]
        _expect(
            grant["issued_at_unix"] <= observed < grant["expires_at_unix"],
            f"{name} grant window changed",
        )
        prior = observed


def _verify_document_snapshot(value: Mapping[str, Any]) -> Mapping[str, Any]:
    _expect(
        set(value) == {"digest", "document", "file"}
        and value["digest"] == canonical_digest(value["document"])
        and value["file"]["digest"] == value["digest"]
        and _verify_file_content(value["file"]) == canonical_json(value["document"]),
        "document snapshot changed",
    )
    return value["document"]


def _verify_grant_state_snapshot(
    value: Mapping[str, Any], grant_digest: str
) -> Mapping[str, Any]:
    document = _verify_document_snapshot(value)
    _verify_control_file(value["file"], "capability-grant-state.json")
    return broker_v4._state(document, grant_digest)


def _verify_control_file(value: Mapping[str, Any], name: str) -> None:
    metadata = value["stat"]
    _expect(
        value["path"] == f"/var/lib/aragorn-runtime-action/control/{name}"
        and metadata["type"] == "file"
        and metadata["uid"] == 995
        and metadata["gid"] == 997
        and metadata["mode"] == "0400"
        and metadata["nlink"] == 1,
        f"control file changed: {name}",
    )


def _verify_clock(value: Mapping[str, Any]) -> tuple[int, int]:
    clocksource = _verify_raw(value["clocksource"])
    proc_uptime = _verify_raw(value["proc_uptime"])
    uptime_match = re.fullmatch(
        rb"([0-9]+(?:\.[0-9]+)?) [0-9]+(?:\.[0-9]+)?\n", proc_uptime
    )
    _expect(
        set(value)
        == {
            "boot_id",
            "boottime_ns",
            "clocksource",
            "monotonic_ns",
            "proc_uptime",
            "realtime_ns",
            "recorded_at",
            "timedatectl",
        }
        and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            value["boot_id"],
        )
        is not None
        and all(
            isinstance(value[field], int)
            and not isinstance(value[field], bool)
            and value[field] > 0
            for field in ("boottime_ns", "monotonic_ns", "realtime_ns")
        )
        and abs(value["boottime_ns"] - value["monotonic_ns"]) < 10_000_000
        and abs(
            int(_time(value["recorded_at"]).timestamp() * 1_000_000_000)
            - value["realtime_ns"]
        )
        < 10_000_000
        and clocksource == b"arch_sys_counter\n"
        and uptime_match is not None
        and abs(
            int(Decimal(uptime_match[1].decode("ascii")) * 1_000_000_000)
            - value["boottime_ns"]
        )
        < 100_000_000,
        "clock record changed",
    )
    timedatectl = value["timedatectl"]
    _expect(
        timedatectl["argv"]
        == ["timedatectl", "show", "--property=NTPSynchronized", "--property=Timezone"]
        and timedatectl["exit_code"] == 0
        and timedatectl["completed_monotonic_ns"] <= value["monotonic_ns"]
        and _verify_raw(timedatectl["stdout"])
        == b"Timezone=Etc/UTC\nNTPSynchronized=yes\n"
        and _verify_raw(timedatectl["stderr"]) == b""
        and bool(clocksource)
        and bool(proc_uptime),
        "clock source changed",
    )
    return value["realtime_ns"], value["monotonic_ns"]


def _ordered_clocks(*values: Mapping[str, Any]) -> None:
    parsed = [_verify_clock(value) for value in values]
    _expect(
        len({value["boot_id"] for value in values}) == 1
        and all(
            left[0] <= right[0] and left[1] <= right[1]
            for left, right in pairwise(parsed)
        ),
        "phase clock ordering changed",
    )


def _verify_effect_snapshot(
    value: Mapping[str, Any], controls: Mapping[str, Any], grant: Mapping[str, Any]
) -> Mapping[str, Any]:
    _expect(
        set(value)
        == {
            "controls",
            "grant_state",
            "pending_exists",
            "protected_entries",
            "receipt_exists",
            "staging_entries",
            "target_exists",
        }
        and all(
            isinstance(value[field], bool)
            for field in ("pending_exists", "receipt_exists", "target_exists")
        )
        and all(
            isinstance(value[field], list)
            and all(isinstance(item, str) for item in value[field])
            for field in ("protected_entries", "staging_entries")
        )
        and set(value["grant_state"]) == {"digest", "document"},
        "effect snapshot changed",
    )
    parent_verifier._bind_controls(value, controls)
    state = broker_v4._state(value["grant_state"]["document"], grant["digest"])
    _expect(
        value["grant_state"]["digest"] == canonical_digest(state),
        "effect grant-state binding changed",
    )
    return state


def _without_grant_state(value: Mapping[str, Any]) -> dict[str, Any]:
    controls = dict(value["controls"])
    controls.pop("capability-grant-state.json")
    return {
        **value,
        "controls": controls,
        "grant_state": None,
    }


def _verify_socket_record(value: Mapping[str, Any], expected_path: str) -> None:
    _expect(
        set(value) == {"metadata", "path", "present", "unix"}
        and value["path"] == expected_path
        and isinstance(value["present"], bool)
        and isinstance(value["unix"], list)
        and all(isinstance(line, str) for line in value["unix"]),
        "socket record changed",
    )
    if not value["present"]:
        _expect(
            value["metadata"] is None and value["unix"] == [], "absent socket changed"
        )
        return
    metadata = value["metadata"]
    _expect(
        set(metadata) == parent_verifier._SOCKET_FIELDS
        and metadata["type"] == "socket"
        and metadata["mode"] == "0660"
        and all(
            isinstance(metadata[field], int)
            and not isinstance(metadata[field], bool)
            and metadata[field] >= 0
            for field in ("device", "gid", "size", "uid")
        )
        and all(
            isinstance(metadata[field], int)
            and not isinstance(metadata[field], bool)
            and metadata[field] > 0
            for field in ("inode", "nlink")
        )
        and metadata["nlink"] == 1
        and metadata["size"] == 0,
        "socket metadata changed",
    )


def _verify_service_snapshot(value: Mapping[str, Any]) -> None:
    unit_names = {
        parent_verifier._GATEWAY_UNIT,
        parent_verifier._WORKER_UNIT,
        parent_verifier._SENSOR_UNIT,
        parent_verifier._BROKER_UNIT,
    }
    socket_paths = {
        "/run/aragorn-runtime-action-worker/worker.sock",
        "/run/aragorn-runtime-observation/sensor.sock",
        "/var/lib/aragorn-runtime-action/control/broker.sock",
    }
    property_options = [
        "-pActiveState",
        "-pSubState",
        "-pResult",
        "-pExecMainCode",
        "-pExecMainStatus",
        "-pMainPID",
        "-pInvocationID",
        "-pUnitFileState",
        "-pControlGroup",
        "-pExecMainStartTimestampMonotonic",
        "-pExecMainExitTimestampMonotonic",
        "-pActiveEnterTimestampMonotonic",
        "-pInactiveEnterTimestampMonotonic",
    ]
    property_names = {option[2:] for option in property_options}
    _expect(
        set(value) == {"sockets", "units"}
        and set(value["units"]) == unit_names
        and set(value["sockets"]) == socket_paths,
        "service snapshot inventory changed",
    )
    for name, entry in value["units"].items():
        _expect(
            set(entry) == {"cgroup_members", "command", "properties"}
            and set(entry["properties"]) == property_names
            and isinstance(entry["cgroup_members"], list)
            and all(
                re.fullmatch(r"[1-9][0-9]*", item) for item in entry["cgroup_members"]
            )
            and entry["command"]["exit_code"] == 0
            and entry["command"]["argv"]
            == ["systemctl", "show", name, *property_options]
            and _verify_raw(entry["command"]["stderr"]) == b"",
            f"service snapshot changed: {name}",
        )
        raw = _verify_raw(entry["command"]["stdout"]).decode("utf-8")
        lines = raw.splitlines()
        _expect(
            len(lines) == len(property_names)
            and all(line.count("=") >= 1 for line in lines),
            f"service snapshot output shape changed: {name}",
        )
        pairs = [line.split("=", 1) for line in lines]
        _expect(
            len({key for key, _value in pairs}) == len(pairs)
            and dict(pairs) == entry["properties"],
            f"service snapshot output changed: {name}",
        )
        main_pid = entry["properties"]["MainPID"]
        invocation = entry["properties"]["InvocationID"]
        transition_times = [
            int(entry["properties"][field])
            for field in (
                "ActiveEnterTimestampMonotonic",
                "ExecMainExitTimestampMonotonic",
                "ExecMainStartTimestampMonotonic",
                "InactiveEnterTimestampMonotonic",
            )
        ]
        _expect(
            entry["properties"]["Result"] == "success"
            and entry["properties"]["ExecMainStatus"] == "0"
            and all(
                re.fullmatch(r"[0-9]+", entry["properties"][field]) is not None
                for field in (
                    "ActiveEnterTimestampMonotonic",
                    "ExecMainExitTimestampMonotonic",
                    "ExecMainStartTimestampMonotonic",
                    "InactiveEnterTimestampMonotonic",
                )
            )
            and (invocation == "" or re.fullmatch(r"[0-9a-f]{32}", invocation))
            and all(
                timestamp * 1_000 <= entry["command"]["completed_monotonic_ns"]
                for timestamp in transition_times
            )
            and entry["cgroup_members"] == ([] if main_pid == "0" else [main_pid]),
            f"service cgroup changed: {name}",
        )
    for path, record in value["sockets"].items():
        _verify_socket_record(record, path)
        if record["present"]:
            expected_owner = {
                "/run/aragorn-runtime-action-worker/worker.sock": (997, 992),
                "/run/aragorn-runtime-observation/sensor.sock": (996, 997),
                "/var/lib/aragorn-runtime-action/control/broker.sock": (995, 996),
            }[path]
            _expect(
                (record["metadata"]["uid"], record["metadata"]["gid"])
                == expected_owner,
                f"service socket owner changed: {path}",
            )
    present_sockets = [
        record for record in value["sockets"].values() if record["present"]
    ]
    _expect(
        len(
            {
                (record["metadata"]["device"], record["metadata"]["inode"])
                for record in present_sockets
            }
        )
        == len(present_sockets),
        "service socket inode closure changed",
    )


def _verify_service_snapshot_window(
    value: Mapping[str, Any], *, after: int, before: int | None = None
) -> None:
    for entry in value["units"].values():
        command = entry["command"]
        _expect(
            after <= command["started_monotonic_ns"]
            and (before is None or command["completed_monotonic_ns"] <= before),
            "service snapshot phase changed",
        )


def _clean_route(value: Mapping[str, Any], *, masked: bool = False) -> bool:
    expected_enablement = {
        parent_verifier._GATEWAY_UNIT: "masked" if masked else "static",
        parent_verifier._WORKER_UNIT: "masked" if masked else "disabled",
        parent_verifier._SENSOR_UNIT: "disabled",
        parent_verifier._BROKER_UNIT: "disabled",
    }
    return all(
        unit["properties"]["ActiveState"] == "inactive"
        and unit["properties"]["SubState"] == "dead"
        and unit["properties"]["Result"] == "success"
        and unit["properties"]["ExecMainStatus"] == "0"
        and unit["properties"]["ExecMainCode"] in {"0", "1"}
        and unit["properties"]["MainPID"] == "0"
        and unit["properties"]["ControlGroup"] == ""
        and unit["properties"]["InvocationID"] == ""
        and unit["properties"]["ExecMainStartTimestampMonotonic"] == "0"
        and unit["properties"]["ExecMainExitTimestampMonotonic"] == "0"
        and unit["properties"]["ActiveEnterTimestampMonotonic"] == "0"
        and unit["properties"]["InactiveEnterTimestampMonotonic"] == "0"
        and unit["properties"]["UnitFileState"] == expected_enablement[name]
        and unit["cgroup_members"] == []
        for name, unit in value["units"].items()
    ) and all(not socket["present"] for socket in value["sockets"].values())


def _verify_cases(
    cases: Mapping[str, Any], boundaries: Mapping[str, Any], context: Mapping[str, Any]
) -> None:
    _expect(
        set(cases)
        == {
            "coherent_consumed",
            "expired_fail_stop",
            "full_activation",
            "terminal_archive_rotation",
        },
        "case inventory changed",
    )
    expired = _verify_expired_case(
        cases["expired_fail_stop"], cases["full_activation"]["stack"], context
    )
    stack = _verify_rotation_case(
        cases["terminal_archive_rotation"], cases["full_activation"], expired, context
    )
    _verify_full_activation(cases["full_activation"], boundaries, stack, context)
    failed_invocations = {
        value["invocation_id"]
        for value in cases["expired_fail_stop"]["activation"]["route"][
            "invocations"
        ].values()
    }
    active_invocations = {
        value["properties"]["InvocationID"]
        for value in stack["service_state"]["units"].values()
    }
    _expect(
        len(failed_invocations | active_invocations) == 6,
        "cross-phase invocation identity collision",
    )
    _verify_coherent_case(
        cases["coherent_consumed"],
        cases["terminal_archive_rotation"],
        stack,
        context,
    )


def _verify_expired_case(
    case: Mapping[str, Any],
    full_stack: Mapping[str, Any],
    context: Mapping[str, Any],
) -> dict[str, Any]:
    check_names = {
        "activation_failed_at_expired_endpoint",
        "available_state_bound",
        "effects_unchanged",
        "expired_broker_stopped",
        "expired_grant_unchanged",
        "expired_services_exited_cleanly",
        "expired_state_bound",
        "expired_state_unchanged",
        "gateway_worker_masked",
        "idle_no_peer_or_effect",
        "invocations_and_timestamps_bound",
        "route_fail_stopped",
        "sensor_broker_disabled",
    }
    _expect(
        set(case) == {"activation", "checks", "expiry", "status"}
        and case["status"] == "OBSERVED"
        and set(case["checks"]) == check_names
        and all(value is True for value in case["checks"].values()),
        "expired case shape changed",
    )
    expiry = case["expiry"]
    _expect(
        set(expiry)
        == {
            "after_route",
            "available_state",
            "available_state_file",
            "broker_start",
            "completed_clock",
            "effects",
            "expired_state",
            "expired_state_file",
            "process",
            "socket",
            "started_clock",
            "trace",
            "unit",
        }
        and set(expiry["effects"]) == {"available", "expired"},
        "expiry phase changed",
    )
    short = context["short_grant"]
    available = _verify_grant_state_snapshot(expiry["available_state"], short["digest"])
    expired = _verify_grant_state_snapshot(expiry["expired_state"], short["digest"])
    _expect(
        expiry["available_state_file"] == expiry["available_state"]["file"]
        and expiry["expired_state_file"] == expiry["expired_state"]["file"]
        and available["status"] == "AVAILABLE"
        and available["claim"] is available["result"] is None
        and expired["status"] == "EXPIRED"
        and expired["claim"] is None
        and expired["result"]
        == broker_v4._expiration_record(
            short["document"], expired["result"]["observed_at_unix"]
        )
        and expired["result"]["observed_at_unix"]
        >= short["document"]["expires_at_unix"],
        "AVAILABLE to EXPIRED state changed",
    )
    available_stat = expiry["available_state_file"]["stat"]
    expired_stat = expiry["expired_state_file"]["stat"]
    short_source_stat = context["short_grant_source"]["file"]["stat"]
    _expect(
        expiry["started_clock"]["realtime_ns"]
        <= available_stat["mtime_ns"]
        <= available_stat["ctime_ns"]
        <= expired_stat["mtime_ns"]
        <= expired_stat["ctime_ns"]
        <= expiry["completed_clock"]["realtime_ns"],
        "expiry state transition timing changed",
    )
    _expect(
        short["document"]["issued_at_unix"] * 1_000_000_000
        <= short_source_stat["mtime_ns"]
        <= short_source_stat["ctime_ns"]
        <= expiry["started_clock"]["realtime_ns"],
        "short grant source timing changed",
    )
    broker_start_completed = int(
        _time(expiry["broker_start"]["completed_at"]).timestamp() * 1_000_000_000
    )
    _expect(
        broker_start_completed <= available_stat["mtime_ns"],
        "AVAILABLE publication preceded broker start",
    )
    _expect(
        available_stat["ctime_ns"]
        < short["document"]["expires_at_unix"] * 1_000_000_000
        <= expired_stat["mtime_ns"]
        and expired["result"]["observed_at_unix"] * 1_000_000_000
        <= expired_stat["mtime_ns"],
        "expiry deadline binding changed",
    )
    terminal_snapshot_started = min(
        int(_time(entry["command"]["started_at"]).timestamp() * 1_000_000_000)
        for entry in expiry["after_route"]["units"].values()
    )
    _expect(
        expired_stat["ctime_ns"] <= terminal_snapshot_started,
        "expiry publication followed terminal snapshot",
    )
    available_effects = expiry["effects"]["available"]
    expired_effects = expiry["effects"]["expired"]
    _expect(
        _verify_effect_snapshot(
            available_effects, context["control_sets"]["expiry"], short
        )
        == available
        and _verify_effect_snapshot(
            expired_effects, context["control_sets"]["expiry"], short
        )
        == expired
        and available_effects["grant_state"]
        == {"digest": expiry["available_state"]["digest"], "document": available}
        and expired_effects["grant_state"]
        == {"digest": expiry["expired_state"]["digest"], "document": expired}
        and _without_grant_state(available_effects)
        == _without_grant_state(expired_effects)
        and available_effects["protected_entries"] == []
        and available_effects["staging_entries"] == []
        and available_effects["pending_exists"] is False
        and available_effects["receipt_exists"] is False
        and available_effects["target_exists"] is False,
        "idle expiry effects changed",
    )
    _ordered_clocks(expiry["started_clock"], expiry["completed_clock"])
    _expect(
        expiry["started_clock"]["realtime_ns"]
        < short["document"]["expires_at_unix"] * 1_000_000_000
        <= expiry["completed_clock"]["realtime_ns"]
        and expiry["broker_start"]["argv"]
        == ["systemctl", "start", parent_verifier._BROKER_UNIT]
        and expiry["broker_start"]["exit_code"] == 0
        and expiry["broker_start"]["stdout"]["digest"] == _raw_digest(b"")
        and expiry["broker_start"]["stderr"]["digest"] == _raw_digest(b"")
        and expiry["started_clock"]["monotonic_ns"]
        <= expiry["broker_start"]["started_monotonic_ns"]
        <= expiry["broker_start"]["completed_monotonic_ns"]
        <= expiry["completed_clock"]["monotonic_ns"],
        "expiry timing changed",
    )
    unit, process = expiry["unit"], expiry["process"]
    reference_unit = full_stack["units"][parent_verifier._BROKER_UNIT]
    reference_process = full_stack["processes"][parent_verifier._BROKER_UNIT]
    loaded_exec, separator, metadata = unit["ExecStart"].partition(" ; ignore_errors=")
    reference_exec = reference_unit["ExecStart"].partition(" ; ignore_errors=")[0]
    metadata_match = re.fullmatch(
        r"no ; start_time=\[[^\]\n]+\] ; stop_time=\[n/a\] ; "
        r"pid=(?P<pid>[1-9][0-9]*) ; code=\(null\) ; status=0/0 \}",
        metadata,
    )
    _expect(
        set(unit) == parent_verifier._UNIT_FIELDS
        and set(process) == parent_verifier._PROCESS_FIELDS
        and canonical_json(
            {key: unit[key] for key in set(unit) - {"ExecStart", "MainPID"}}
        )
        == canonical_json(
            {
                key: reference_unit[key]
                for key in set(reference_unit) - {"ExecStart", "MainPID"}
            }
        )
        and canonical_json(
            {key: process[key] for key in set(process) - {"pid", "start_time_ticks"}}
        )
        == canonical_json(
            {
                key: reference_process[key]
                for key in set(reference_process) - {"pid", "start_time_ticks"}
            }
        )
        and unit["ActiveState"] == "active"
        and unit["SubState"] == "running"
        and isinstance(unit["MainPID"], str)
        and re.fullmatch(r"[1-9][0-9]*", unit["MainPID"]) is not None
        and isinstance(process["pid"], int)
        and not isinstance(process["pid"], bool)
        and unit["MainPID"] == "216"
        and process["pid"] == 216
        and isinstance(process["start_time_ticks"], str)
        and process["start_time_ticks"] == "29775073"
        and bool(separator)
        and loaded_exec == reference_exec
        and metadata_match is not None
        and int(metadata_match["pid"]) == process["pid"]
        and unit["ControlGroup"]
        == f"/docker/{context['container_id']}/system.slice/{parent_verifier._BROKER_UNIT}"
        and process["uids"] == [995, 995, 995, 995]
        and process["gids"] == [997, 997, 997, 997]
        and process["groups"] == [996, 997]
        and process["capabilities_effective"] == "0000000000000000"
        and isinstance(process["no_new_privileges"], int)
        and not isinstance(process["no_new_privileges"], bool)
        and process["no_new_privileges"] == 1,
        "expiry broker process changed",
    )
    _verify_socket_record(
        expiry["socket"], "/var/lib/aragorn-runtime-action/control/broker.sock"
    )
    _expect(
        expiry["socket"]["metadata"]["uid"] == context["identities"]["broker"]["uid"]
        and expiry["socket"]["metadata"]["gid"]
        == context["identities"]["sensor"]["gid"]
        and len(
            {
                (
                    record["device"],
                    record["inode"],
                )
                for record in (
                    context["short_grant_source"]["file"]["stat"],
                    expiry["available_state_file"]["stat"],
                    expiry["expired_state_file"]["stat"],
                    expiry["socket"]["metadata"],
                )
            }
        )
        == 4,
        "expiry broker socket changed",
    )
    trace = expiry["trace"]
    core_trace = {
        key: trace[key]
        for key in (
            "channels",
            "raw",
            "raw_bytes",
            "raw_digest",
            "service_pid",
            "successful_connects",
        )
    }
    parent_verifier._verify_trace(core_trace, unix_only_service=True)
    _expect(
        set(trace)
        == {
            "channels",
            "raw",
            "raw_bytes",
            "raw_digest",
            "service_pid",
            "successful_accepts",
            "successful_connects",
            "tracer",
        }
        and trace["service_pid"] == process["pid"]
        and trace["channels"] == trace["successful_accepts"] == []
        and trace["successful_connects"] == []
        and parent_verifier._connect_attempt_paths(core_trace) == []
        and set(trace["tracer"]) == {"covered_terminal_state", "exit_code", "stderr"}
        and trace["tracer"]["covered_terminal_state"] is True
        and isinstance(trace["tracer"]["exit_code"], int)
        and not isinstance(trace["tracer"]["exit_code"], bool)
        and trace["tracer"]["exit_code"] == 0
        and _verify_raw(trace["tracer"]["stderr"])
        == f"strace: Process {process['pid']} attached\n".encode("ascii"),
        "expiry trace changed",
    )
    _verify_service_snapshot(expiry["after_route"])
    _verify_service_snapshot_window(
        expiry["after_route"],
        after=expiry["broker_start"]["completed_monotonic_ns"],
        before=expiry["completed_clock"]["monotonic_ns"],
    )
    broker_after = expiry["after_route"]["units"][parent_verifier._BROKER_UNIT]
    _expect(
        _clean_route(expiry["after_route"])
        and broker_after["properties"]["ActiveState"] == "inactive"
        and broker_after["properties"]["MainPID"] == "0"
        and broker_after["cgroup_members"] == []
        and not expiry["after_route"]["sockets"][
            "/var/lib/aragorn-runtime-action/control/broker.sock"
        ]["present"],
        "expired broker did not stop",
    )
    _verify_failed_activation(case["activation"], expiry, short, context)
    return {
        "activation_completed_clock": case["activation"]["completed_clock"],
        "activation_route_after": case["activation"]["route"]["after"],
        "expired_state": expiry["expired_state"],
        "expired_effects": expired_effects,
    }


def _verify_failed_activation(
    activation: Mapping[str, Any],
    expiry: Mapping[str, Any],
    short_grant: Mapping[str, Any],
    context: Mapping[str, Any],
) -> None:
    _expect(
        set(activation)
        == {
            "command",
            "completed_clock",
            "effects",
            "grant",
            "journals",
            "route",
            "started_clock",
            "state",
        }
        and set(activation["state"]) == {"after", "after_file", "before", "before_file"}
        and set(activation["grant"]) == {"after", "before"}
        and set(activation["effects"]) == {"after", "before"}
        and set(activation["route"]) == {"after", "before", "invocations", "monitor"},
        "failed activation shape changed",
    )
    command = activation["command"]
    _ordered_clocks(
        expiry["completed_clock"],
        activation["started_clock"],
        activation["completed_clock"],
    )
    stderr = _verify_raw(command["stderr"])
    _expect(
        command["argv"]
        == ["/usr/libexec/aragorn/activate-runtime-action-worker-host.sh"]
        and command["exit_code"] == 1
        and command["signal"] is None
        and _verify_raw(command["stdout"]) == b""
        and bool(stderr.splitlines())
        and _raw_digest(stderr)
        == "sha256:4ef35b169c8416c9ddc6dbc32a7bd40041e9f73457178b7f99cd3be910238271"
        and stderr.splitlines()[-1]
        == b"runtime worker endpoint did not become ready: "
        b"/var/lib/aragorn-runtime-action/control/broker.sock"
        and activation["started_clock"]["monotonic_ns"]
        <= command["started_monotonic_ns"]
        <= command["completed_monotonic_ns"]
        <= command["monitor_completed_monotonic_ns"]
        <= activation["completed_clock"]["monotonic_ns"],
        "expired activation command changed",
    )
    state = activation["state"]
    grant = activation["grant"]
    effects = activation["effects"]
    _expect(
        canonical_json(state["before"])
        == canonical_json(state["after"])
        == canonical_json(expiry["expired_state"])
        and state["before_file"] == state["before"]["file"]
        and state["after_file"] == state["after"]["file"]
        and canonical_json(grant["before"])
        == canonical_json(grant["after"])
        == canonical_json(context["short_grant_source"])
        and canonical_json(effects["before"])
        == canonical_json(effects["after"])
        == canonical_json(expiry["effects"]["expired"]),
        "expired activation mutated retained state",
    )
    before, after = activation["route"]["before"], activation["route"]["after"]
    _verify_service_snapshot(before)
    _verify_service_snapshot(after)
    _verify_service_snapshot_window(
        before,
        after=expiry["completed_clock"]["monotonic_ns"],
        before=command["started_monotonic_ns"],
    )
    _verify_service_snapshot_window(after, after=command["completed_monotonic_ns"])
    _expect(
        _service_semantics(before) == _service_semantics(expiry["after_route"])
        and _clean_route(after, masked=True)
        and after["units"][parent_verifier._GATEWAY_UNIT]["properties"]["UnitFileState"]
        == "masked"
        and after["units"][parent_verifier._WORKER_UNIT]["properties"]["UnitFileState"]
        == "masked"
        and after["units"][parent_verifier._SENSOR_UNIT]["properties"]["UnitFileState"]
        == "disabled"
        and after["units"][parent_verifier._BROKER_UNIT]["properties"]["UnitFileState"]
        == "disabled",
        "expired activation fail-stop changed",
    )
    samples = activation["route"]["monitor"]
    invocations = activation["route"]["invocations"]
    names = {parent_verifier._BROKER_UNIT, parent_verifier._SENSOR_UNIT}
    _expect(
        isinstance(samples, list)
        and bool(samples)
        and set(invocations) == names
        and set(activation["journals"]) == names,
        "activation monitor inventory changed",
    )
    for sample in samples:
        _verify_monitor_sample(sample, names)
    observed_times = [sample["observed_monotonic_ns"] for sample in samples]
    _expect(
        command["started_monotonic_ns"] <= observed_times[0]
        and all(left < right for left, right in pairwise(observed_times))
        and observed_times[-1] <= command["monitor_completed_monotonic_ns"],
        "activation monitor timing changed",
    )
    observed_invocations = set()
    for name in names:
        derived = _derive_monitored_invocation(
            samples,
            name,
            before["units"][name]["properties"]["InvocationID"],
            command,
        )
        _expect(invocations[name] == derived, f"activation invocation changed: {name}")
        observed_invocations.add(derived["invocation_id"])
        unit_file_states = [
            sample["units"][name]["UnitFileState"] for sample in derived["samples"]
        ]
        first_disabled = unit_file_states.index("disabled")
        _expect(
            all(state == "disabled" for state in unit_file_states[first_disabled:]),
            f"activation unit enablement changed: {name}",
        )
        journal = activation["journals"][name]
        _expect(
            journal["exit_code"] == 0
            and journal["argv"]
            == [
                "journalctl",
                "--no-pager",
                "--output=short-monotonic",
                f"_SYSTEMD_INVOCATION_ID={derived['invocation_id']}",
            ]
            and command["monitor_completed_monotonic_ns"]
            <= journal["started_monotonic_ns"]
            <= journal["completed_monotonic_ns"]
            and _verify_raw(journal["stdout"]) == b"-- No entries --\n"
            and _verify_raw(journal["stderr"]) == b"",
            f"activation journal changed: {name}",
        )
    _expect(
        len(observed_invocations) == len(names),
        "activation invocation identity collision",
    )


def _service_semantics(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "sockets": value["sockets"],
        "units": {
            name: {
                "cgroup_members": entry["cgroup_members"],
                "properties": entry["properties"],
            }
            for name, entry in value["units"].items()
        },
    }


def _verify_monitor_sample(value: Mapping[str, Any], names: set[str]) -> None:
    properties = {
        "ActiveState",
        "ExecMainCode",
        "ExecMainExitTimestampMonotonic",
        "ExecMainStartTimestampMonotonic",
        "ExecMainStatus",
        "Id",
        "InvocationID",
        "MainPID",
        "Result",
        "SubState",
        "UnitFileState",
    }
    _expect(
        set(value) == {"observed_monotonic_ns", "units"}
        and isinstance(value["observed_monotonic_ns"], int)
        and not isinstance(value["observed_monotonic_ns"], bool)
        and value["observed_monotonic_ns"] > 0
        and set(value["units"]) == names
        and all(
            set(unit) == properties
            and all(isinstance(item, str) for item in unit.values())
            and unit["Id"] == name
            and (
                unit["InvocationID"] == ""
                or re.fullmatch(r"[0-9a-f]{32}", unit["InvocationID"])
            )
            for name, unit in value["units"].items()
        ),
        "activation monitor sample changed",
    )
    active_pids = []
    for unit in value["units"].values():
        start = int(unit["ExecMainStartTimestampMonotonic"])
        exit_time = int(unit["ExecMainExitTimestampMonotonic"])
        pid = int(unit["MainPID"])
        common = (
            unit["Result"] == "success"
            and unit["ExecMainStatus"] == "0"
            and unit["UnitFileState"] in {"disabled", "enabled"}
            and start * 1_000 <= value["observed_monotonic_ns"]
            and exit_time * 1_000 <= value["observed_monotonic_ns"]
        )
        if unit["InvocationID"] == "":
            valid_state = (
                unit["ActiveState"] == "inactive"
                and unit["SubState"] == "dead"
                and unit["ExecMainCode"] == "0"
                and pid == start == exit_time == 0
            )
        else:
            valid_state = (
                (
                    unit["ActiveState"] == "active"
                    and unit["SubState"] == "running"
                    and unit["ExecMainCode"] == "0"
                    and pid > 0
                    and start > 0
                    and exit_time == 0
                )
                or (
                    unit["ActiveState"] == "deactivating"
                    and unit["SubState"] == "stop-sigterm"
                    and unit["ExecMainCode"] == "0"
                    and pid > 0
                    and start > 0
                    and exit_time == 0
                )
                or (
                    unit["ActiveState"] == "inactive"
                    and unit["SubState"] == "dead"
                    and unit["ExecMainCode"] == "1"
                    and pid == 0
                    and 0 < start <= exit_time
                )
            )
        _expect(common and valid_state, "activation monitor service state changed")
        if pid:
            active_pids.append(pid)
    _expect(
        len(set(active_pids)) == len(active_pids),
        "activation monitor process identity collision",
    )


def _derive_monitored_invocation(
    samples: list[Mapping[str, Any]],
    name: str,
    previous_invocation: str,
    command: Mapping[str, Any],
) -> dict[str, Any]:
    candidates: dict[str, list[Mapping[str, Any]]] = {}
    for sample in samples:
        invocation = sample["units"][name]["InvocationID"]
        if invocation and invocation != previous_invocation:
            candidates.setdefault(invocation, []).append(sample)
    _expect(len(candidates) == 1, f"unit invocation was not observed: {name}")
    invocation, retained = next(iter(candidates.items()))
    state_rank = {"active": 0, "deactivating": 1, "inactive": 2}
    states = [sample["units"][name]["ActiveState"] for sample in retained]
    positive_pids = {
        int(sample["units"][name]["MainPID"])
        for sample in retained
        if sample["units"][name]["MainPID"] != "0"
    }
    _expect(
        all(state in state_rank for state in states)
        and all(
            state_rank[left] <= state_rank[right] for left, right in pairwise(states)
        )
        and len(positive_pids) == 1,
        f"unit invocation lifecycle changed: {name}",
    )
    starts = {
        int(sample["units"][name]["ExecMainStartTimestampMonotonic"])
        for sample in retained
        if sample["units"][name]["ExecMainStartTimestampMonotonic"] not in {"", "0"}
    }
    exits = {
        int(sample["units"][name]["ExecMainExitTimestampMonotonic"])
        for sample in retained
        if sample["units"][name]["ExecMainExitTimestampMonotonic"] not in {"", "0"}
    }
    start = next(iter(starts)) if len(starts) == 1 else None
    terminal = retained[-1]
    same_invocation_exit = (
        start is not None
        and len(exits) == 1
        and start <= next(iter(exits))
        and next(iter(exits)) * 1_000 <= terminal["observed_monotonic_ns"]
        and terminal["units"][name]["ActiveState"] == "inactive"
        and terminal["units"][name]["SubState"] == "dead"
        and terminal["units"][name]["MainPID"] == "0"
        and terminal["units"][name]["ExecMainCode"] == "1"
        and terminal["units"][name]["ExecMainStatus"] == "0"
        and terminal["units"][name]["UnitFileState"] == "disabled"
    )
    cleared = next(
        (
            sample
            for sample in samples
            if sample["observed_monotonic_ns"] > terminal["observed_monotonic_ns"]
            and _cleared_properties(sample["units"][name])
        ),
        None,
    )
    cleared_success = (
        not exits
        and cleared is not None
        and terminal["units"][name]["ActiveState"] == "deactivating"
        and terminal["units"][name]["SubState"] == "stop-sigterm"
        and re.fullmatch(r"[1-9][0-9]*", terminal["units"][name]["MainPID"]) is not None
        and terminal["units"][name]["ExecMainCode"] == "0"
        and terminal["units"][name]["ExecMainStatus"] == "0"
        and terminal["units"][name]["UnitFileState"] == "disabled"
    )
    observation = terminal if same_invocation_exit else cleared
    _expect(
        start is not None
        and command["started_monotonic_ns"]
        <= start * 1_000
        <= command["completed_monotonic_ns"]
        and observation is not None
        and observation["observed_monotonic_ns"]
        <= command["monitor_completed_monotonic_ns"]
        and any(int(sample["units"][name]["MainPID"]) > 0 for sample in retained)
        and all(
            int(sample["units"][name]["ExecMainStartTimestampMonotonic"]) * 1_000
            <= sample["observed_monotonic_ns"]
            for sample in retained
            if sample["units"][name]["ExecMainStartTimestampMonotonic"] not in {"", "0"}
        )
        and all(sample["units"][name]["Result"] == "success" for sample in retained)
        and (same_invocation_exit or cleared_success),
        f"unit invocation timing changed: {name}",
    )
    return {
        "invocation_id": invocation,
        "samples": retained,
        "terminal_observation": (
            "same_invocation_exit"
            if same_invocation_exit
            else "same_invocation_started_then_cleared"
        ),
    }


def _cleared_properties(value: Mapping[str, Any]) -> bool:
    return (
        value["ActiveState"] == "inactive"
        and value["SubState"] == "dead"
        and value["Result"] == "success"
        and value["MainPID"] == "0"
        and value["ExecMainCode"] == "0"
        and value["ExecMainStatus"] == "0"
        and value["ExecMainStartTimestampMonotonic"] == "0"
        and value["ExecMainExitTimestampMonotonic"] == "0"
        and value["InvocationID"] == ""
        and value["UnitFileState"] == "disabled"
    )


def _verify_rotation_case(
    case: Mapping[str, Any],
    full_case: Mapping[str, Any],
    expired: Mapping[str, Any],
    context: Mapping[str, Any],
) -> Mapping[str, Any]:
    check_names = {
        "archive_metadata",
        "exact_control_inventory_no_stage_or_receipt",
        "expired_state_archived_exactly",
        "four_units_active_no_boot_authority",
        "fresh_grant_distinct_and_available",
        "rotation_changed_only_grant_state",
    }
    _expect(
        set(case)
        == {
            "activation_command",
            "after",
            "before",
            "checks",
            "grant_replacement",
            "status",
            "unmask_command",
        }
        and case["status"] == "OBSERVED"
        and set(case["checks"]) == check_names
        and all(value is True for value in case["checks"].values())
        and case["activation_command"] == full_case["activation_command"],
        "rotation case shape changed",
    )
    before, after = case["before"], case["after"]
    replacement = case["grant_replacement"]
    _expect(
        set(before)
        == {
            "archive_paths",
            "clock",
            "control_entries",
            "effects",
            "expired_state",
            "expired_state_file",
            "grant_source",
            "route",
        }
        and set(after)
        == {
            "archive",
            "archive_file",
            "clock",
            "control_entries",
            "current_state",
            "current_state_file",
            "effects",
            "expired_profile_receipt_archive_present",
            "grant_source",
            "route",
        }
        and set(replacement) == {"completed", "file", "grant", "started"},
        "rotation phase shape changed",
    )
    short, fresh = context["short_grant"], context["fresh_grant"]
    archive_name = broker_v4._archive_name("state", short["digest"])
    receipt_archive_name = broker_v4._archive_name("profile-receipt", short["digest"])
    control_root = "/var/lib/aragorn-runtime-action/control/"
    _expect(
        canonical_json(before["archive_paths"])
        == canonical_json(
            {
                "profile_receipt": {
                    "path": control_root + receipt_archive_name,
                    "present": False,
                },
                "state": {"path": control_root + archive_name, "present": False},
            }
        ),
        "rotation archive precondition changed",
    )
    expired_document = _verify_grant_state_snapshot(
        before["expired_state"], short["digest"]
    )
    archive_document = _verify_document_snapshot(after["archive"])
    current_document = _verify_grant_state_snapshot(
        after["current_state"], fresh["digest"]
    )
    _expect(
        before["expired_state"] == expired["expired_state"]
        and before["expired_state_file"] == before["expired_state"]["file"]
        and broker_v4._state(expired_document, short["digest"])["status"] == "EXPIRED"
        and broker_v4._state(archive_document, short["digest"])["status"] == "EXPIRED"
        and archive_document == expired_document
        and after["archive"]["digest"] == before["expired_state"]["digest"]
        and after["archive"]["file"]["base64"]
        == before["expired_state"]["file"]["base64"]
        and after["archive"]["file"]["path"] == control_root + archive_name
        and after["archive_file"] == after["archive"]["file"]
        and after["archive_file"]["stat"]["uid"]
        == context["identities"]["broker"]["uid"]
        and after["archive_file"]["stat"]["gid"]
        == context["identities"]["worker"]["gid"]
        and after["archive_file"]["stat"]["mode"] == "0400"
        and after["archive_file"]["stat"]["nlink"] == 1,
        "expired archive changed",
    )
    available = broker_v4._state(current_document, fresh["digest"])
    _expect(
        available["status"] == "AVAILABLE"
        and available["claim"] is available["result"] is None
        and after["current_state_file"] == after["current_state"]["file"]
        and after["current_state_file"]["path"]
        == control_root + "capability-grant-state.json"
        and after["expired_profile_receipt_archive_present"] is False,
        "fresh AVAILABLE state changed",
    )
    for record in (after["archive_file"], after["current_state_file"]):
        _expect(
            before["clock"]["realtime_ns"]
            <= record["stat"]["mtime_ns"]
            <= record["stat"]["ctime_ns"]
            <= after["clock"]["realtime_ns"],
            "rotation file transition timing changed",
        )
    activation_wall_start = int(
        _time(case["activation_command"]["started_at"]).timestamp() * 1_000_000_000
    )
    activation_wall_completed = int(
        _time(case["activation_command"]["completed_at"]).timestamp() * 1_000_000_000
    )
    _expect(
        activation_wall_start
        <= after["archive_file"]["stat"]["mtime_ns"]
        <= after["archive_file"]["stat"]["ctime_ns"]
        <= after["current_state_file"]["stat"]["mtime_ns"],
        "rotation archive publication order changed",
    )
    _expect(
        after["current_state_file"]["stat"]["mtime_ns"]
        <= after["current_state_file"]["stat"]["ctime_ns"]
        <= activation_wall_completed,
        "rotation activation publication timing changed",
    )
    replacement_grant = _verify_document_snapshot(replacement["grant"])
    _expect(
        replacement["file"] == replacement["grant"]["file"]
        and replacement["grant"] == before["grant_source"] == after["grant_source"]
        and replacement["grant"] == context["fresh_grant_source"]
        and replacement_grant == fresh["document"]
        and replacement["grant"]["digest"] == fresh["digest"],
        "grant replacement changed",
    )
    _expect(
        expired["activation_completed_clock"]["realtime_ns"]
        <= replacement["file"]["stat"]["mtime_ns"]
        <= replacement["file"]["stat"]["ctime_ns"]
        <= replacement["completed"]["realtime_ns"],
        "grant replacement timing changed",
    )
    _expect(
        replacement["started"]["realtime_ns"]
        <= replacement["file"]["stat"]["ctime_ns"],
        "grant replacement start timing changed",
    )
    before_state = _verify_effect_snapshot(
        before["effects"], context["control_sets"]["activation"], short
    )
    after_state = _verify_effect_snapshot(
        after["effects"], context["control_sets"]["activation"], fresh
    )
    _expect(
        before_state == expired_document
        and after_state == available
        and _without_grant_state(before["effects"])
        == _without_grant_state(after["effects"])
        and before["effects"]["pending_exists"] is False
        and before["effects"]["receipt_exists"] is False
        and before["effects"]["target_exists"] is False,
        "rotation effects changed",
    )
    expected_before_entries = [
        "broker.instance.lock",
        "broker.lock",
        "capability-grant-state.json",
        "health.json",
        "observation.json",
        "policy.json",
        "revocations.json",
        "state.json",
    ]
    _expect(
        before["control_entries"] == expected_before_entries
        and after["control_entries"]
        == sorted([*expected_before_entries, archive_name, "broker.sock"])
        and not any(name.startswith(".") for name in after["control_entries"]),
        "rotation control inventory changed",
    )
    unmask, activation = case["unmask_command"], case["activation_command"]
    _expect(
        unmask["argv"]
        == [
            "systemctl",
            "unmask",
            parent_verifier._GATEWAY_UNIT,
            parent_verifier._WORKER_UNIT,
        ]
        and unmask["exit_code"] == 0
        and unmask["stdout"]["digest"] == _raw_digest(b"")
        and unmask["stderr"]["digest"]
        == "sha256:dd88d24266865dc6f905788b3444925da883b6dc9ceff2538736e15e0a174588"
        and activation["argv"]
        == ["/usr/libexec/aragorn/activate-runtime-action-worker-host.sh"]
        and activation["exit_code"] == 0
        and activation["stdout"]["digest"] == _raw_digest(b"")
        and activation["stderr"]["digest"]
        == "sha256:ea6d30b09e201d538622d2bd92ecbe0bb47924edcb383aebda5bc86a657b6413",
        "rotation commands changed",
    )
    _verify_service_snapshot_window(
        expired["activation_route_after"],
        after=0,
        before=unmask["started_monotonic_ns"],
    )
    _ordered_clocks(
        expired["activation_completed_clock"],
        replacement["started"],
        replacement["completed"],
        before["clock"],
        after["clock"],
    )
    _expect(
        expired["activation_completed_clock"]["monotonic_ns"]
        <= unmask["started_monotonic_ns"]
        <= unmask["completed_monotonic_ns"]
        <= replacement["started"]["monotonic_ns"]
        and _time(expired["activation_completed_clock"]["recorded_at"])
        <= _time(unmask["started_at"])
        and before["clock"]["monotonic_ns"]
        <= activation["started_monotonic_ns"]
        <= activation["completed_monotonic_ns"]
        <= after["clock"]["monotonic_ns"]
        and fresh["document"]["issued_at_unix"]
        <= before["clock"]["realtime_ns"] // 1_000_000_000
        < fresh["document"]["expires_at_unix"],
        "rotation timing changed",
    )
    _verify_service_snapshot(before["route"])
    _verify_service_snapshot(after["route"])
    _verify_service_snapshot_window(
        before["route"],
        after=replacement["completed"]["monotonic_ns"],
        before=activation["started_monotonic_ns"],
    )
    _verify_service_snapshot_window(
        full_case["stack"]["service_state"],
        after=activation["completed_monotonic_ns"],
        before=after["clock"]["monotonic_ns"],
    )
    _verify_service_snapshot_window(
        after["route"],
        after=activation["completed_monotonic_ns"],
        before=after["clock"]["monotonic_ns"],
    )
    _expect(
        _clean_route(before["route"])
        and canonical_json(_service_semantics(after["route"]))
        == canonical_json(_service_semantics(full_case["stack"]["service_state"])),
        "rotation route changed",
    )
    _expect(
        (
            before["expired_state_file"]["stat"]["device"],
            before["expired_state_file"]["stat"]["inode"],
        )
        != (
            before["grant_source"]["file"]["stat"]["device"],
            before["grant_source"]["file"]["stat"]["inode"],
        ),
        "rotation precondition inode closure changed",
    )
    identities = [
        (record["stat"]["device"], record["stat"]["inode"])
        for record in (
            after["archive_file"],
            after["current_state_file"],
            after["grant_source"]["file"],
        )
    ] + [
        (record["metadata"]["device"], record["metadata"]["inode"])
        for record in after["route"]["sockets"].values()
        if record["present"]
    ]
    _expect(
        len(set(identities)) == len(identities),
        "rotation object inode closure changed",
    )
    return full_case["stack"]


def _verify_full_activation(
    case: Mapping[str, Any],
    boundaries: Mapping[str, Any],
    stack: Mapping[str, Any],
    context: Mapping[str, Any],
) -> None:
    unit_names = {
        parent_verifier._GATEWAY_UNIT,
        parent_verifier._WORKER_UNIT,
        parent_verifier._SENSOR_UNIT,
        parent_verifier._BROKER_UNIT,
    }
    socket_paths = {
        "/run/aragorn-runtime-action-worker/worker.sock",
        "/run/aragorn-runtime-observation/sensor.sock",
        "/var/lib/aragorn-runtime-action/control/broker.sock",
    }
    _expect(
        set(case) == {"activation_command", "checks", "stack", "status"}
        and case["status"] == "OBSERVED"
        and case["stack"] is stack
        and set(case["checks"])
        == {
            "four_units_active",
            "gateway_listener_bound_to_main_pid",
            "no_boot_authority",
            "three_sockets_present",
        }
        and all(value is True for value in case["checks"].values())
        and set(stack)
        == {
            "enablement",
            "gateway_listener",
            "pids",
            "processes",
            "service_state",
            "sockets",
            "units",
        }
        and set(stack["pids"])
        == set(stack["processes"])
        == set(stack["units"])
        == set(stack["enablement"])
        == unit_names
        and set(stack["sockets"]) == socket_paths,
        "full activation shape changed",
    )
    _verify_p37c_unit_contracts(stack["units"], stack["processes"])
    expected_process = {
        parent_verifier._GATEWAY_UNIT: {
            "gids": [992, 992, 992, 992],
            "groups": [992],
            "uids": [992, 992, 992, 992],
        },
        parent_verifier._WORKER_UNIT: {
            "gids": [997, 997, 997, 997],
            "groups": [992, 997],
            "uids": [997, 997, 997, 997],
        },
        parent_verifier._BROKER_UNIT: {
            "gids": [997, 997, 997, 997],
            "groups": [996, 997],
            "uids": [995, 995, 995, 995],
        },
        parent_verifier._SENSOR_UNIT: {
            "gids": [996, 996, 996, 997],
            "groups": [996, 997],
            "uids": [996, 996, 996, 997],
        },
    }
    for name, process in stack["processes"].items():
        pid = stack["pids"][name]
        _expect(
            set(process) == parent_verifier._PROCESS_FIELDS
            and set(stack["units"][name]) == parent_verifier._UNIT_FIELDS
            and isinstance(pid, int)
            and not isinstance(pid, bool)
            and pid > 0
            and isinstance(stack["units"][name]["MainPID"], str)
            and re.fullmatch(r"[1-9][0-9]*", stack["units"][name]["MainPID"])
            is not None
            and process["pid"] == pid == int(stack["units"][name]["MainPID"])
            and {field: process[field] for field in ("gids", "groups", "uids")}
            == expected_process[name]
            and process["capabilities_effective"] == "0000000000000000"
            and isinstance(process["no_new_privileges"], int)
            and not isinstance(process["no_new_privileges"], bool)
            and process["no_new_privileges"] == 1
            and re.fullmatch(r"[1-9][0-9]*", process["start_time_ticks"]) is not None
            and abs(
                int(
                    stack["service_state"]["units"][name]["properties"][
                        "ExecMainStartTimestampMonotonic"
                    ]
                )
                - int(process["start_time_ticks"]) * 10_000
            )
            < 20_000
            and re.fullmatch(r"mnt:\[[1-9][0-9]*\]", process["mount_namespace"])
            is not None
            and re.fullmatch(r"net:\[[1-9][0-9]*\]", process["network_namespace"])
            is not None
            and stack["units"][name]["ControlGroup"]
            == f"/docker/{context['container_id']}/system.slice/{name}",
            f"activated process changed: {name}",
        )
    _expect(
        len({value["mount_namespace"] for value in stack["processes"].values()}) == 4
        and len({value["network_namespace"] for value in stack["processes"].values()})
        == 4
        and len(set(stack["pids"].values())) == 4
        and stack["enablement"]
        == {
            parent_verifier._GATEWAY_UNIT: "static",
            parent_verifier._WORKER_UNIT: "disabled",
            parent_verifier._SENSOR_UNIT: "disabled",
            parent_verifier._BROKER_UNIT: "disabled",
        },
        "activation isolation or boot authority changed",
    )
    _verify_service_snapshot(stack["service_state"])
    _expect(
        stack["sockets"] == stack["service_state"]["sockets"],
        "activation socket snapshots changed",
    )
    for name, entry in stack["service_state"]["units"].items():
        started = int(entry["properties"]["ExecMainStartTimestampMonotonic"])
        active = int(entry["properties"]["ActiveEnterTimestampMonotonic"])
        _expect(
            entry["properties"]["ActiveState"] == "active"
            and entry["properties"]["SubState"] == "running"
            and entry["properties"]["Result"] == "success"
            and entry["properties"]["ExecMainCode"] == "0"
            and entry["properties"]["ExecMainStatus"] == "0"
            and case["activation_command"]["started_monotonic_ns"]
            <= started * 1_000
            <= active * 1_000
            <= case["activation_command"]["completed_monotonic_ns"]
            and entry["properties"]["ExecMainExitTimestampMonotonic"] == "0"
            and entry["properties"]["InactiveEnterTimestampMonotonic"] == "0"
            and int(entry["properties"]["MainPID"]) == stack["pids"][name]
            and entry["properties"]["InvocationID"]
            and entry["properties"]["UnitFileState"] == stack["enablement"][name]
            and entry["properties"]["ControlGroup"]
            == stack["units"][name]["ControlGroup"],
            f"activated service changed: {name}",
        )
    _expect(
        len(
            {
                entry["properties"]["InvocationID"]
                for entry in stack["service_state"]["units"].values()
            }
        )
        == len(unit_names),
        "activated service invocation closure changed",
    )
    expected_socket_owner = {
        "/run/aragorn-runtime-action-worker/worker.sock": (997, 992),
        "/run/aragorn-runtime-observation/sensor.sock": (996, 997),
        "/var/lib/aragorn-runtime-action/control/broker.sock": (995, 996),
    }
    for path, record in stack["sockets"].items():
        _verify_socket_record(record, path)
        uid, gid = expected_socket_owner[path]
        _expect(
            record["present"]
            and record["metadata"]["uid"] == uid
            and record["metadata"]["gid"] == gid,
            f"activated socket changed: {path}",
        )
    listener = stack["gateway_listener"]
    tcp_raw = _verify_raw(listener["proc_net_tcp"]).decode("ascii")
    matches = [
        line
        for line in tcp_raw.splitlines()[1:]
        if len(line.split()) >= 10
        and line.split()[1] == "0100007F:4965"
        and line.split()[3] == "0A"
    ]
    _expect(
        set(listener) == {"fd_owners", "listener", "pid", "proc_net_tcp"}
        and listener["pid"] == stack["pids"][parent_verifier._GATEWAY_UNIT]
        and len(matches) == 1
        and listener["listener"]
        == {"inode": int(matches[0].split()[9]), "line": matches[0]}
        and isinstance(listener["fd_owners"], list)
        and len(listener["fd_owners"]) == 1
        and re.fullmatch(r"/proc/[1-9][0-9]*/fd/[1-9][0-9]*", listener["fd_owners"][0])
        is not None
        and f"/proc/{listener['pid']}/fd/" in listener["fd_owners"][0],
        "gateway listener changed",
    )
    _expect(
        set(boundaries)
        == {
            "activation_lock",
            "enablement",
            "gateway_listener",
            "processes",
            "service_state",
            "sockets",
            "units",
        }
        and boundaries["activation_lock"]
        == "/run/lock/aragorn-runtime-capability-activation.lock"
        and all(
            canonical_json(boundaries[field]) == canonical_json(stack[field])
            for field in (
                "enablement",
                "gateway_listener",
                "processes",
                "service_state",
                "sockets",
                "units",
            )
        ),
        "retained activation boundary changed",
    )


def _verify_p37c_unit_contracts(
    units: Mapping[str, Any], processes: Mapping[str, Any]
) -> None:
    normalized = {name: dict(unit) for name, unit in units.items()}
    for name in (parent_verifier._BROKER_UNIT, parent_verifier._SENSOR_UNIT):
        loaded, separator, metadata = units[name]["ExecStart"].partition(
            " ; ignore_errors="
        )
        _expect(
            separator
            and metadata
            == "no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; "
            "code=(null) ; status=0/0 }",
            f"retained ExecStart display changed: {name}",
        )
        normalized[name]["ExecStart"] = (
            f"{loaded} ; ignore_errors=no ; start_time=[retained] ; "
            f"stop_time=[n/a] ; pid={processes[name]['pid']} ; "
            "code=(null) ; status=0/0 }"
        )
    parent_verifier._verify_unit_contracts(normalized, processes)


def _verify_coherent_case(
    case: Mapping[str, Any],
    rotation: Mapping[str, Any],
    stack: Mapping[str, Any],
    context: Mapping[str, Any],
) -> None:
    check_names = {
        "clean_before_after",
        "driver_completed_allow_created",
        "effect_bound",
        "exact_peer_chain",
        "grant_consumed_once",
        "lease_bound",
        "one_connect_no_retry",
        "receipt_result_bound",
        "route_completion",
        "transcript_join",
        "worker_attributed",
    }
    _expect(
        set(case)
        == {
            "broker_journal_after",
            "broker_state",
            "checks",
            "correlation",
            "driver",
            "effects",
            "expired_archive_after",
            "grant_state",
            "grant_state_file",
            "receipt",
            "receipt_file",
            "service_pids",
            "service_state_after",
            "status",
            "target",
            "traces",
        }
        and case["status"] == "OBSERVED"
        and set(case["checks"]) == check_names
        and all(value is True for value in case["checks"].values()),
        "coherent case shape changed",
    )
    _expect(
        parent_verifier._verify_driver("coherent", case["driver"]) == 14,
        "coherent driver closure changed",
    )
    _expect(
        case["driver"]["output"]["provider"]["records"][1][
            "message_prefix_continuity_valid"
        ]
        is True,
        "coherent provider continuity changed",
    )
    provider_time = int(
        _time(
            case["driver"]["output"]["provider"]["records"][0]["received_at"]
        ).timestamp()
    )
    fresh = context["fresh_grant"]
    _expect(
        fresh["document"]["issued_at_unix"]
        <= provider_time
        < fresh["document"]["expires_at_unix"],
        "coherent driver grant window changed",
    )
    receipt_document = _verify_document_snapshot(case["receipt"])
    broker_state_document = _verify_document_snapshot(case["broker_state"])
    _verify_control_file(case["receipt"]["file"], "profile-receipt.json")
    _verify_control_file(case["broker_state"]["file"], "state.json")
    grant_state_document = _verify_grant_state_snapshot(
        case["grant_state"], fresh["digest"]
    )
    _expect(
        case["receipt_file"] == case["receipt"]["file"]
        and case["grant_state_file"] == case["grant_state"]["file"]
        and case["effects"]["after"]["grant_state"]
        == {
            "digest": case["grant_state"]["digest"],
            "document": grant_state_document,
        }
        and broker._state(broker_state_document) == broker_state_document,
        "coherent retained document binding changed",
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
        "grant": fresh,
        "policy": context["policy"],
        "producer": context["producer"],
        "profiles": context["profiles"],
    }
    parent_verifier._verify_snapshot_binding("coherent", projected, legacy_context)
    parent_verifier._verify_coherent(projected, legacy_context)
    _expect(
        broker_v4._state(grant_state_document, fresh["digest"])["status"] == "CONSUMED",
        "coherent grant was not consumed",
    )
    traces = case["traces"]
    _expect(
        set(traces) == {"broker", "gateway", "sensor", "worker"},
        "coherent trace inventory changed",
    )
    _verify_gateway_trace(traces["gateway"])
    for name in ("worker", "sensor", "broker"):
        parent_verifier._verify_trace(traces[name], unix_only_service=True)
    identities = context["identities"]
    expected_channels = {
        "gateway": [],
        "worker": [
            {
                "kind": "accept",
                "path": None,
                "peer": {
                    "gid": identities["gateway"]["gid"],
                    "pid": traces["gateway"]["service_pid"],
                    "uid": identities["gateway"]["uid"],
                },
            },
            {
                "kind": "connect",
                "path": "/run/aragorn-runtime-observation/sensor.sock",
                "peer": {
                    "gid": identities["sensor"]["gid"],
                    "pid": traces["sensor"]["service_pid"],
                    "uid": identities["sensor"]["uid"],
                },
            },
        ],
        "sensor": [
            {
                "kind": "accept",
                "path": None,
                "peer": {
                    "gid": identities["worker"]["gid"],
                    "pid": traces["worker"]["service_pid"],
                    "uid": identities["worker"]["uid"],
                },
            },
            {
                "kind": "connect",
                "path": "/var/lib/aragorn-runtime-action/control/broker.sock",
                "peer": {
                    "gid": identities["worker"]["gid"],
                    "pid": traces["broker"]["service_pid"],
                    "uid": identities["broker"]["uid"],
                },
            },
        ],
        "broker": [
            {
                "kind": "accept",
                "path": None,
                "peer": {
                    "gid": identities["sensor"]["gid"],
                    "pid": traces["sensor"]["service_pid"],
                    "uid": identities["sensor"]["uid"],
                },
            }
        ],
    }
    _expect(
        all(
            traces[name]["channels"] == expected
            for name, expected in expected_channels.items()
        )
        and parent_verifier._connect_attempt_paths(traces["worker"])
        == ["/run/aragorn-runtime-observation/sensor.sock"]
        and parent_verifier._connect_attempt_paths(traces["sensor"])
        == ["/var/lib/aragorn-runtime-action/control/broker.sock"]
        and parent_verifier._connect_attempt_paths(traces["broker"]) == [],
        "coherent peer route changed",
    )
    before_pids = case["service_pids"]["before"]
    after_pids = case["service_pids"]["after"]
    service_names = {
        parent_verifier._GATEWAY_UNIT,
        parent_verifier._WORKER_UNIT,
        parent_verifier._SENSOR_UNIT,
        parent_verifier._BROKER_UNIT,
    }
    _expect(
        set(case["service_pids"]) == {"after", "before"}
        and set(before_pids) == set(after_pids) == service_names
        and all(
            isinstance(pid, int) and not isinstance(pid, bool) and pid >= 0
            for pid in after_pids.values()
        )
        and before_pids == stack["pids"]
        and {
            "gateway": before_pids[parent_verifier._GATEWAY_UNIT],
            "worker": before_pids[parent_verifier._WORKER_UNIT],
            "sensor": before_pids[parent_verifier._SENSOR_UNIT],
            "broker": before_pids[parent_verifier._BROKER_UNIT],
        }
        == {name: trace["service_pid"] for name, trace in traces.items()}
        and all(
            after_pids[name] == before_pids[name]
            for name in (
                parent_verifier._GATEWAY_UNIT,
                parent_verifier._WORKER_UNIT,
                parent_verifier._SENSOR_UNIT,
            )
        )
        and after_pids[parent_verifier._BROKER_UNIT] == 0,
        "coherent service identity changed",
    )
    _verify_service_snapshot(case["service_state_after"])
    _expect(
        all(
            _time(entry["command"]["started_at"])
            >= _time(case["driver"]["output"]["timing"]["completed_at"])
            for entry in case["service_state_after"]["units"].values()
        ),
        "coherent service snapshot phase changed",
    )
    after_units = case["service_state_after"]["units"]
    for name in (
        parent_verifier._GATEWAY_UNIT,
        parent_verifier._WORKER_UNIT,
        parent_verifier._SENSOR_UNIT,
    ):
        _expect(
            after_units[name]["properties"]["ActiveState"] == "active"
            and after_units[name]["properties"]["SubState"] == "running"
            and after_units[name]["properties"]["Result"] == "success"
            and after_units[name]["properties"]["ExecMainCode"] == "0"
            and after_units[name]["properties"]["ExecMainStatus"] == "0"
            and after_units[name]["properties"]["ExecMainStartTimestampMonotonic"]
            == stack["service_state"]["units"][name]["properties"][
                "ExecMainStartTimestampMonotonic"
            ]
            and after_units[name]["properties"]["ActiveEnterTimestampMonotonic"]
            == stack["service_state"]["units"][name]["properties"][
                "ActiveEnterTimestampMonotonic"
            ]
            and after_units[name]["properties"]["ExecMainExitTimestampMonotonic"] == "0"
            and after_units[name]["properties"]["InactiveEnterTimestampMonotonic"]
            == "0"
            and int(after_units[name]["properties"]["MainPID"]) == before_pids[name]
            and after_units[name]["properties"]["InvocationID"]
            == stack["service_state"]["units"][name]["properties"]["InvocationID"]
            and after_units[name]["properties"]["UnitFileState"]
            == stack["enablement"][name]
            and after_units[name]["properties"]["ControlGroup"]
            == stack["units"][name]["ControlGroup"],
            f"coherent retained service changed: {name}",
        )
    broker_after = after_units[parent_verifier._BROKER_UNIT]
    broker_before = stack["service_state"]["units"][parent_verifier._BROKER_UNIT][
        "properties"
    ]
    broker_start = int(broker_after["properties"]["ExecMainStartTimestampMonotonic"])
    broker_active = int(broker_after["properties"]["ActiveEnterTimestampMonotonic"])
    broker_exit = int(broker_after["properties"]["ExecMainExitTimestampMonotonic"])
    broker_inactive = int(broker_after["properties"]["InactiveEnterTimestampMonotonic"])
    phase_clock = rotation["after"]["clock"]
    clock_offset = phase_clock["realtime_ns"] - phase_clock["monotonic_ns"]
    driver_started = (
        int(
            _time(case["driver"]["output"]["timing"]["started_at"]).timestamp()
            * 1_000_000_000
        )
        - clock_offset
    )
    driver_completed = (
        int(
            _time(case["driver"]["output"]["timing"]["completed_at"]).timestamp()
            * 1_000_000_000
        )
        - clock_offset
    )
    provider_started = (
        int(
            _time(
                case["driver"]["output"]["provider"]["records"][0]["received_at"]
            ).timestamp()
            * 1_000_000_000
        )
        - clock_offset
    )
    provider_completed = (
        int(
            _time(
                case["driver"]["output"]["provider"]["records"][1]["received_at"]
            ).timestamp()
            * 1_000_000_000
        )
        - clock_offset
    )
    _expect(
        broker_after["properties"]["ActiveState"] == "inactive"
        and broker_after["properties"]["SubState"] == "dead"
        and broker_after["properties"]["Result"] == "success"
        and broker_after["properties"]["ExecMainCode"] == "1"
        and broker_after["properties"]["ExecMainStatus"] == "0"
        and broker_after["properties"]["ExecMainStartTimestampMonotonic"]
        == broker_before["ExecMainStartTimestampMonotonic"]
        and broker_after["properties"]["ActiveEnterTimestampMonotonic"]
        == broker_before["ActiveEnterTimestampMonotonic"]
        and broker_start <= broker_active <= broker_exit <= broker_inactive
        and driver_started <= broker_exit * 1_000 <= driver_completed
        and provider_started <= broker_exit * 1_000 <= provider_completed
        and broker_inactive * 1_000 <= broker_after["command"]["started_monotonic_ns"]
        and broker_after["properties"]["MainPID"] == "0"
        and broker_after["properties"]["ControlGroup"] == ""
        and broker_after["properties"]["InvocationID"]
        == stack["service_state"]["units"][parent_verifier._BROKER_UNIT]["properties"][
            "InvocationID"
        ]
        and broker_after["properties"]["UnitFileState"] == "disabled"
        and broker_after["cgroup_members"] == []
        and not case["service_state_after"]["sockets"][
            "/var/lib/aragorn-runtime-action/control/broker.sock"
        ]["present"]
        and case["service_state_after"]["sockets"][
            "/run/aragorn-runtime-action-worker/worker.sock"
        ]["present"]
        and case["service_state_after"]["sockets"][
            "/run/aragorn-runtime-observation/sensor.sock"
        ]["present"],
        "coherent broker teardown changed",
    )
    provider_wall_start = int(
        _time(
            case["driver"]["output"]["provider"]["records"][0]["received_at"]
        ).timestamp()
        * 1_000_000_000
    )
    provider_wall_completed = int(
        _time(
            case["driver"]["output"]["provider"]["records"][1]["received_at"]
        ).timestamp()
        * 1_000_000_000
    )
    action_files = [
        case["target"],
        case["broker_state"]["file"],
        case["receipt"]["file"],
        case["grant_state"]["file"],
    ]
    _expect(
        all(
            provider_wall_start
            <= record["stat"]["mtime_ns"]
            <= record["stat"]["ctime_ns"]
            <= provider_wall_completed
            for record in action_files
        )
        and [record["stat"]["ctime_ns"] for record in action_files]
        == sorted(record["stat"]["ctime_ns"] for record in action_files),
        "coherent file transition timing changed",
    )
    _expect(
        max(record["stat"]["ctime_ns"] for record in action_files) - clock_offset
        <= broker_exit * 1_000,
        "coherent broker exited before retained effects",
    )
    identities = [
        (record["stat"]["device"], record["stat"]["inode"])
        for record in (
            case["broker_state"]["file"],
            case["grant_state"]["file"],
            case["receipt"]["file"],
            case["target"],
            case["expired_archive_after"]["file"],
            context["fresh_grant_source"]["file"],
        )
    ] + [
        (record["metadata"]["device"], record["metadata"]["inode"])
        for record in case["service_state_after"]["sockets"].values()
        if record["present"]
    ]
    _expect(
        len(set(identities)) == len(identities),
        "coherent object inode closure changed",
    )
    journal = case["broker_journal_after"]
    broker_invocation = stack["service_state"]["units"][parent_verifier._BROKER_UNIT][
        "properties"
    ]["InvocationID"]
    _expect(
        journal["exit_code"] == 0
        and journal["argv"]
        == [
            "journalctl",
            "--no-pager",
            "--output=short-monotonic",
            f"_SYSTEMD_INVOCATION_ID={broker_invocation}",
        ]
        and _verify_raw(journal["stdout"]) == b"-- No entries --\n"
        and _verify_raw(journal["stderr"]) == b""
        and broker_inactive * 1_000 <= journal["started_monotonic_ns"],
        "coherent broker journal changed",
    )
    _expect(
        case["expired_archive_after"] == rotation["after"]["archive"],
        "expired archive changed after coherent action",
    )


def _verify_gateway_trace(trace: Mapping[str, Any]) -> None:
    raw = trace["raw"].encode("utf-8")
    worker_path = "/run/aragorn-runtime-action-worker/worker.sock"
    route_paths = {
        worker_path,
        "/run/aragorn-runtime-observation/sensor.sock",
        "/var/lib/aragorn-runtime-action/control/broker.sock",
    }
    _expect(
        set(trace)
        == {
            "channels",
            "raw",
            "raw_bytes",
            "raw_digest",
            "service_pid",
            "successful_connects",
        }
        and trace["raw_bytes"] == len(raw) <= 64 * 1024
        and trace["raw_digest"] == _raw_digest(raw)
        and isinstance(trace["service_pid"], int)
        and not isinstance(trace["service_pid"], bool)
        and trace["service_pid"] > 0
        and trace["channels"] == [],
        "gateway trace changed",
    )
    attempts = []
    connects = []
    for line in trace["raw"].splitlines():
        if not any(path in line for path in route_paths):
            continue
        attempt = parent_verifier._CONNECT_ATTEMPT_TRACE.fullmatch(line)
        _expect(attempt is not None, "unparsed gateway worker connect")
        _expect(
            int(attempt["service"]) == trace["service_pid"],
            "gateway worker connect identity changed",
        )
        attempts.append(attempt["path"])
        connected = parent_verifier._CONNECT_TRACE.fullmatch(line)
        if connected is not None:
            connects.append({"fd": int(connected["fd"]), "path": connected["path"]})
    _expect(
        attempts == [worker_path]
        and connects == trace["successful_connects"]
        and len(connects) == 1
        and connects[0]["path"] == worker_path
        and "SO_PEERCRED" not in trace["raw"],
        "gateway worker route changed",
    )


def _verify_secrets(value: Mapping[str, Any], cases: Mapping[str, Any]) -> None:
    retained_raw: list[bytes] = []

    def collect(candidate: Any) -> None:
        if isinstance(candidate, Mapping):
            if set(candidate) == {"base64", "bytes", "digest"}:
                retained_raw.append(_verify_raw(candidate))
            else:
                for child in candidate.values():
                    collect(child)
        elif isinstance(candidate, list):
            for child in candidate:
                collect(child)

    collect(cases)
    _expect(
        canonical_json(value)
        == canonical_json(
            {
                "forbidden_driver_fields": [],
                "gateway_environment_bytes_retained": False,
                "gateway_environment_digest_retained": False,
                "provider_and_gateway_token_values_retained": False,
            }
        )
        and parent_verifier._forbidden_driver_fields(
            cases["coherent_consumed"]["driver"]
        )
        == []
        and all(
            marker not in raw
            for raw in retained_raw
            for marker in (
                b"OPENCLAW_GATEWAY_TOKEN=",
                b"ARAGORN_MOCK_PROVIDER_TOKEN=",
                b"Authorization: Bearer ",
            )
        ),
        "secret or authority ceiling changed",
    )


def _verify_records(document: Mapping[str, Any]) -> None:
    documents: list[Mapping[str, Any]] = []
    files: list[Mapping[str, Any]] = []
    raw_records: list[Mapping[str, Any]] = []
    commands: list[Mapping[str, Any]] = []
    sockets: list[Mapping[str, Any]] = []
    clocks: list[Mapping[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            if "digest" in value and isinstance(value.get("document"), Mapping):
                documents.append(value)
            if {"bytes", "digest", "path", "stat"}.issubset(value):
                files.append(value)
            if set(value) == {"base64", "bytes", "digest"}:
                raw_records.append(value)
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
                commands.append(value)
            if (
                set(value) == {"metadata", "path", "present", "unix"}
                and value["present"] is True
            ):
                sockets.append(value)
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
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    _expect(len(documents) == 31, "digest-document closure changed")
    _expect(len(files) == 129, "file-record closure changed")
    _expect(len(raw_records) == 118, "raw-record closure changed")
    _expect(len(commands) == 48, "command-record closure changed")
    _expect(len(clocks) == 8, "clock-record closure changed")
    for pair in documents:
        _expect(
            pair["digest"] == canonical_digest(pair["document"]),
            "retained document digest changed",
        )
    for record in files:
        _verify_file(record)
    for record in raw_records:
        _verify_raw(record)
    for command in commands:
        _verify_command(command)
    clock_offsets = [clock["realtime_ns"] - clock["monotonic_ns"] for clock in clocks]
    capture_start = min(_time(clock["recorded_at"]) for clock in clocks)
    capture_end = _time(document["recorded_at"])
    for command in commands:
        pairs = [
            (command["started_at"], command["started_monotonic_ns"]),
            (command["completed_at"], command["completed_monotonic_ns"]),
        ]
        if "monitor_completed_at" in command:
            pairs.append(
                (
                    command["monitor_completed_at"],
                    command["monitor_completed_monotonic_ns"],
                )
            )
        _expect(
            all(
                capture_start - timedelta(seconds=1) <= _time(wall) <= capture_end
                and min(
                    abs(
                        int(_time(wall).timestamp() * 1_000_000_000)
                        - monotonic
                        - offset
                    )
                    for offset in clock_offsets
                )
                < 20_000_000
                for wall, monotonic in pairs
            ),
            "command clock binding changed",
        )
    artifacts = document["artifacts"]
    persistent = [artifacts["worker_installer"], document["harness"]["file"]]
    for pair in [*artifacts["installed"], *artifacts["plugin"]["files"]]:
        persistent.extend((pair["source"], pair["installed"]))
    persistent_identities = {
        (record["stat"]["device"], record["stat"]["inode"]): record["path"]
        for record in persistent
    }
    _expect(
        len(persistent_identities) == len(persistent),
        "persistent file inode closure changed",
    )
    for path, identity in [
        *(
            (
                record["path"],
                (record["stat"]["device"], record["stat"]["inode"]),
            )
            for record in files
        ),
        *(
            (
                record["path"],
                (
                    record["metadata"]["device"],
                    record["metadata"]["inode"],
                ),
            )
            for record in sockets
        ),
    ]:
        _expect(
            identity not in persistent_identities
            or persistent_identities[identity] == path,
            "persistent file identity was reused",
        )


def _verify_raw(value: Mapping[str, Any]) -> bytes:
    _expect(set(value) == {"base64", "bytes", "digest"}, "raw record changed")
    raw = base64.b64decode(value["base64"], validate=True)
    _expect(
        isinstance(value["bytes"], int)
        and not isinstance(value["bytes"], bool)
        and value["bytes"] == len(raw)
        and value["digest"] == _raw_digest(raw),
        "raw record identity changed",
    )
    return raw


def _verify_file(value: Mapping[str, Any]) -> None:
    has_raw = "base64" in value
    expected_fields = {"bytes", "digest", "path", "stat"}
    if has_raw:
        expected_fields.add("base64")
    stat_value = value["stat"]
    expected_stat_fields = {
        "device",
        "gid",
        "inode",
        "mode",
        "nlink",
        "size",
        "type",
        "uid",
    }
    if has_raw:
        expected_stat_fields.update({"ctime_ns", "mtime_ns"})
    _expect(
        set(value) == expected_fields
        and set(stat_value) == expected_stat_fields
        and isinstance(value["path"], str)
        and value["path"].startswith("/")
        and _DIGEST.fullmatch(value["digest"]) is not None
        and isinstance(value["bytes"], int)
        and not isinstance(value["bytes"], bool)
        and value["bytes"] >= 0
        and stat_value["type"] == "file"
        and isinstance(stat_value["mode"], str)
        and re.fullmatch(r"[0-7]{4}", stat_value["mode"]) is not None
        and all(
            isinstance(stat_value[field], int)
            and not isinstance(stat_value[field], bool)
            and stat_value[field] >= 0
            for field in (
                {"device", "gid", "size", "uid"}
                | ({"ctime_ns", "mtime_ns"} if has_raw else set())
            )
        )
        and all(
            isinstance(stat_value[field], int)
            and not isinstance(stat_value[field], bool)
            and stat_value[field] > 0
            for field in ("inode", "nlink")
        )
        and value["bytes"] == stat_value["size"],
        "retained file record changed",
    )
    if has_raw:
        raw = base64.b64decode(value["base64"], validate=True)
        _expect(
            len(raw) == value["bytes"] and _raw_digest(raw) == value["digest"],
            "retained file content changed",
        )


def _verify_command(value: Mapping[str, Any]) -> None:
    base_fields = {
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
    }
    monitored = "monitor_completed_at" in value
    expected_fields = base_fields | (
        {"monitor_completed_at", "monitor_completed_monotonic_ns"}
        if monitored
        else set()
    )
    caller = value["caller"]
    _expect(
        set(value) == expected_fields
        and set(caller) == {"gid", "uid"}
        and caller == {"gid": 0, "uid": 0}
        and all(
            isinstance(caller[field], int)
            and not isinstance(caller[field], bool)
            and caller[field] >= 0
            for field in ("gid", "uid")
        )
        and isinstance(value["argv"], list)
        and bool(value["argv"])
        and all(isinstance(item, str) and item for item in value["argv"])
        and isinstance(value["started_monotonic_ns"], int)
        and not isinstance(value["started_monotonic_ns"], bool)
        and isinstance(value["completed_monotonic_ns"], int)
        and not isinstance(value["completed_monotonic_ns"], bool)
        and value["started_monotonic_ns"] <= value["completed_monotonic_ns"]
        and value["elapsed_ns"]
        == value["completed_monotonic_ns"] - value["started_monotonic_ns"]
        and _time(value["started_at"]) <= _time(value["completed_at"]),
        "command timing or identity changed",
    )
    exit_code, signal = value["exit_code"], value["signal"]
    _expect(
        (exit_code is None) != (signal is None)
        and (
            exit_code is None
            or (
                isinstance(exit_code, int)
                and not isinstance(exit_code, bool)
                and exit_code >= 0
            )
        )
        and (
            signal is None
            or (isinstance(signal, int) and not isinstance(signal, bool) and signal > 0)
        ),
        "command result changed",
    )
    _verify_raw(value["stdout"])
    _verify_raw(value["stderr"])
    if monitored:
        _expect(
            isinstance(value["monitor_completed_monotonic_ns"], int)
            and not isinstance(value["monitor_completed_monotonic_ns"], bool)
            and value["completed_monotonic_ns"]
            <= value["monitor_completed_monotonic_ns"]
            and _time(value["completed_at"]) <= _time(value["monitor_completed_at"]),
            "command monitor timing changed",
        )


def _verify_artifacts(value: Mapping[str, Any]) -> None:
    _expect(
        set(value)
        == {
            "collector",
            "installed",
            "installed_closure_digest",
            "obsolete_shims_absent",
            "plugin",
            "worker_installer",
        },
        "artifact fields changed",
    )
    collector = value["collector"]
    _expect(
        set(collector)
        == {
            "base_installer",
            "capture_recipe",
            "dockerfile",
            "driver",
            "parent_probe",
            "probe",
        }
        and canonical_digest(collector) == _COLLECTOR_DIGEST,
        "collector closure changed",
    )
    installed = value["installed"]
    plugin = value["plugin"]
    _expect(
        isinstance(installed, list)
        and len(installed) == 40
        and set(plugin) == {"digest", "files"}
        and isinstance(plugin["files"], list)
        and len(plugin["files"]) == 3,
        "installed inventory changed",
    )
    pairs = [*installed, *plugin["files"]]
    identity = []
    source_identity = []
    for pair in pairs:
        _expect(set(pair) == {"installed", "source"}, "installed pair changed")
        source, target = pair["source"], pair["installed"]
        expected_mode = "0755" if "/usr/libexec/" in target["path"] else "0644"
        _expect(
            (source["digest"], source["bytes"]) == (target["digest"], target["bytes"])
            and source["stat"]["uid"] == source["stat"]["gid"] == 0
            and source["stat"]["nlink"] == 1
            and source["stat"]["mode"] in {"0444", "0555", "0644"}
            and target["stat"]["uid"] == target["stat"]["gid"] == 0
            and target["stat"]["nlink"] == 1
            and target["stat"]["mode"] == expected_mode,
            "source/install binding changed",
        )
        identity.append(
            {
                "bytes": target["bytes"],
                "digest": target["digest"],
                "mode": target["stat"]["mode"],
                "path": target["path"],
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
    pair_identity = [
        {
            "source": pair["source"]["path"],
            "installed": pair["installed"]["path"],
            "digest": pair["installed"]["digest"],
            "bytes": pair["installed"]["bytes"],
            "mode": pair["installed"]["stat"]["mode"],
        }
        for pair in pairs
    ]
    _expect(
        canonical_digest(pair_identity) == _PAIR_CLOSURE_DIGEST
        and canonical_digest(source_identity) == _SOURCE_CLOSURE_DIGEST
        and canonical_digest(identity) == _INSTALLED_CLOSURE_DIGEST
        and value["installed_closure_digest"] == _INSTALLED_CLOSURE_DIGEST
        and canonical_digest(value["obsolete_shims_absent"]) == _OBSOLETE_SHIMS_DIGEST,
        "installed implementation closure changed",
    )
    worker_installer = value["worker_installer"]
    _expect(
        worker_installer["path"]
        == "/src/packaging/install-runtime-action-worker-host.sh"
        and worker_installer["digest"]
        == "sha256:885441b628298629cc07d5c68e52b852864c6a755bc10d0e7e5de406f17b4748"
        and worker_installer["bytes"] == 1_240
        and worker_installer["stat"]["type"] == "file"
        and worker_installer["stat"]["uid"] == worker_installer["stat"]["gid"] == 0
        and worker_installer["stat"]["mode"] == "0555"
        and worker_installer["stat"]["nlink"] == 1,
        "worker installer changed",
    )
    artifact_records = [
        worker_installer,
        *(record for pair in pairs for record in (pair["source"], pair["installed"])),
    ]
    _expect(
        len({record["path"] for record in artifact_records})
        == len(artifact_records)
        == len(
            {
                (record["stat"]["device"], record["stat"]["inode"])
                for record in artifact_records
            }
        ),
        "artifact inode closure changed",
    )
    plugin_identity = [
        {
            "digest": pair["installed"]["digest"],
            "executable": bool(int(pair["installed"]["stat"]["mode"], 8) & 0o111),
            "kind": "file",
            "links": pair["installed"]["stat"]["nlink"],
            "path": Path(pair["installed"]["path"]).name,
            "size": pair["installed"]["bytes"],
        }
        for pair in plugin["files"]
    ]
    _expect(plugin["digest"] == canonical_digest(plugin_identity), "plugin changed")


def _verify_harness(value: Mapping[str, Any]) -> None:
    _expect(set(value) == {"digest", "document", "file"}, "harness fields changed")
    harness = value["document"]
    _expect(
        value["digest"] == canonical_digest(harness) == _HARNESS_DIGEST
        and _verify_file_content(value["file"]) == canonical_json(harness),
        "harness identity changed",
    )
    _expect(
        value["file"]["path"] == "/run/aragorn-harness.json"
        and value["file"]["stat"]["uid"] == value["file"]["stat"]["gid"] == 0
        and value["file"]["stat"]["mode"] == "0600"
        and value["file"]["stat"]["nlink"] == 1,
        "harness file changed",
    )
    _expect(
        set(harness)
        == {
            "capture_disposition",
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
            "run_image_reference",
            "schema",
            "source_commit",
            "source_commit_verification",
        }
        and harness["schema"]
        == "aragorn/runtime-action-worker-activation-expiry-systemd-harness/v1"
        and harness["capture_disposition"]
        == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and re.fullmatch(r"[0-9a-f]{64}", harness["container_id"]) is not None
        and harness["source_commit"] == _SOURCE_COMMIT
        and harness["parent_image_id"] == _PARENT_IMAGE
        and harness["image_id"] == harness["run_image_reference"] == _CHILD_IMAGE
        and harness["profile_label"] == "p3.7c"
        and harness["platform"] == "linux"
        and canonical_digest(harness["image_lineage"]) == _IMAGE_LINEAGE_DIGEST,
        "harness implementation binding changed",
    )
    lineage = harness["image_lineage"]
    _expect(
        set(lineage) == {"added_layers", "child", "parent"}
        and lineage["parent"]["id"] == _PARENT_IMAGE
        and lineage["child"]["id"] == _CHILD_IMAGE
        and lineage["parent"]["rootfs_type"]
        == lineage["child"]["rootfs_type"]
        == "layers"
        and lineage["child"]["layers"]
        == [*lineage["parent"]["layers"], *lineage["added_layers"]]
        and len(lineage["added_layers"]) == 5,
        "image lineage changed",
    )
    _expect(
        harness["host_config"]
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
        }
        and harness["openclaw_runtime_volume"] == "aragorn-openclaw-2026-7-1-runtime"
        and harness["openclaw_runtime_mount"]
        == {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": "aragorn-openclaw-2026-7-1-runtime",
            "type": "volume",
        }
        and harness["openclaw_runtime_volume_identity"]
        == {
            "driver": "local",
            "labels": None,
            "name": "aragorn-openclaw-2026-7-1-runtime",
            "options": None,
            "scope": "local",
        },
        "harness isolation changed",
    )
    verification = harness["source_commit_verification"]
    commit_raw = _verify_raw(verification["commit_object"])
    commit_identity = hashlib.sha1(
        f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
    ).hexdigest()
    _expect(
        set(verification)
        == {"command", "commit_object", "exit_code", "stderr", "stdout"}
        and verification["command"] == ["git", "verify-commit", "--raw", _SOURCE_COMMIT]
        and verification["exit_code"] == 0
        and commit_identity == _SOURCE_COMMIT
        and b"gpgsig " in commit_raw
        and _verify_raw(verification["stdout"]) == b""
        and b'Good "git" signature' in _verify_raw(verification["stderr"]),
        "source commit verification changed",
    )


def _verify_file_content(value: Mapping[str, Any]) -> bytes:
    _verify_file(value)
    _expect("base64" in value, "retained file content is absent")
    return base64.b64decode(value["base64"], validate=True)


def _verify_parent(value: Mapping[str, Any]) -> None:
    _expect(
        value
        == {
            "observation": {
                "path": parent_verifier._RETAINED_PATH,
                "bytes": parent_verifier._EVIDENCE_BYTES,
                "raw_digest": parent_verifier._EVIDENCE_RAW_DIGEST,
                "canonical_digest": parent_verifier._EVIDENCE_DIGEST,
            },
            "receipt": {
                "path": _PARENT_RECEIPT_PATH,
                "bytes": _PARENT_RECEIPT_BYTES,
                "raw_digest": _PARENT_RECEIPT_RAW_DIGEST,
                "canonical_digest": _PARENT_RECEIPT_DIGEST,
            },
            "verifier_digest": _PARENT_VERIFIER_DIGEST,
            "schema_digest": (
                "sha256:753e18cb7fd0df2eae5cb12a1b29e6e9be798162ed108114f681077d7fd2968a"
            ),
            "decision_status": "P3_7B_BOUNDED_PASS",
        },
        "parent binding changed",
    )


def _raw_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _expect(condition: Any, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(message)
