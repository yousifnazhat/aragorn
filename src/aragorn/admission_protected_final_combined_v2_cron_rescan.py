"""Add one cron-rescan PASS to the verified two-route V2 qualification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_cron as cron
from . import admission_protected_final_combined_v2_prompt_rebuild as parent
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError

_ROUTE = "ADM-02/reload/cron-rescan"
_PASS_ROUTES = {
    "ADM-02/reload/fresh-session-reset",
    "ADM-02/reload/missing-prompt-blob-rebuild",
    _ROUTE,
}
_PARENT_DIGEST = (
    "sha256:5c978e1a1fa600bb1e22cb08e1555f7ed3da8dd30d87a65e60655a3e730bbebc"
)
_PARENT_VERIFIER = (
    "sha256:6518ada93011ed91bd5a5d3a7d53a599603be863d9dea1427441628bab08a3ee"
)
_CRON_VERIFIER = (
    "sha256:e0cbfb701345e834bfcaa8a29e34660d90dd9a5cd1a7b45de35c6ee330465e65"
)
_EVIDENCE = {
    "bytes": 595_057,
    "canonical_bytes": 595_056,
    "canonical_digest": (
        "sha256:9e1c6534237c1b98820d50739901aec082a088188abc42f2366f6d69d5698a00"
    ),
    "digest": (
        "sha256:c2c68ea14a1e06d9d9e7ebad65e30b48c6c1430216bc9e1b7f2dd1e321e1990e"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-"
        "cron-rescan-systemd-p3-final-store-bound-2026-08-22.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 93_612,
    "canonical_digest": (
        "sha256:b3ba988399363da47c1d81b8e3854b860f7b1c1118207e97246a611eb0e29b9d"
    ),
    "digest": (
        "sha256:20018e3adaa45ab6bd48a802b075175781fceab1e1301b7805eb69df23015c21"
    ),
}
_SOURCE = {
    "commit": "c20ea9a9692bb65c2c0155087b6756c75292e895",
    "parent": "d672d43fa39aa4b6c0431a9ff257b3c0379e43dd",
    "tree": "a3fed368818c8656bace4ff67d82d5794598bb4a",
}
_RETENTION = {
    "commit": "efd59694433f18a0d54d0299601ca52465715634",
    "parent": _SOURCE["commit"],
    "tree": "3abf080e684586fb603d5f431f4e74fd7cc9a9ae",
}
_RETENTION_BLOB = "e924165d3dbeb0cba64446a082135dbb53394078"
_IMAGE = "sha256:d40892e8fca9ce2c5fd3b381c95cb4df8ff1c3f27f101802ac9c936ca2fdd35e"
_IMAGE_LINEAGE_DIGEST = (
    "sha256:42e1a3e2fd42353353e65604e91fa6b64ee1c6fca72781eec4a1f799b0a0d35d"
)
_HOST_CONFIG_DIGEST = (
    "sha256:8a35e5d3dbbe4b9bdd8ebf9ed05bf5d9bb39a380870770ebeba66797f65c950c"
)
_HARNESS_DIGEST = (
    "sha256:fe827ac338b35628c3f6bd095e7823a2ab219dca335d8f3ec66f42efd370420d"
)
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v2-route-input-64792"
_ACTION_DIGEST = (
    "sha256:9529f817b74cc8dd4f0a2813a8613983e7f49e425353cafddb165752509e1ad4"
)
_COMPOSITION_ACTION_DIGEST = (
    "sha256:dcf1b7bd609616985338caa2cb01c9d5610d437003206125c9656d60b3cd0672"
)
_SOURCE_ARTIFACTS = {
    "collector": {
        "bytes": 9_473,
        "digest": (
            "sha256:b61f513560dc6ff9808a4b68f66adafa1f681b1f5fbc984fc67781a7cf2dfbdd"
        ),
    },
    "helper": dict(parent._SOURCE_ARTIFACTS["helper"]),
    "materializer": {
        "bytes": 74_674,
        "digest": (
            "sha256:1352bfa238e32af0127bf4e438a4e01fbf9ae0974b91284cb11f95f36543ecd2"
        ),
    },
    "probe": {
        "bytes": 35_318,
        "digest": (
            "sha256:94d3b47162fd1bdc97028f44115ef54acfe8b7a296210a47a8a24a71771bb2d0"
        ),
    },
    "v1_route_injector": dict(parent._SOURCE_ARTIFACTS["v1_route_injector"]),
}
_STATIC_DIGESTS = {
    "boundary": "sha256:8e0df898fde9878a6c04540a612db4d7ae93ca73b3ff6cca3e6f8e2a9ee0538f",
    "config": "sha256:2441d3d26c6991c40c67bedf71357ab2fa856a44ba35e6f3a1f0a4480bda881b",
    "config_tree": "sha256:2e65adf6c0214ed2689ab7a4a0c8a34d54376885a14f6390fd695329cccef917",
    "gateway": "sha256:08d28111316c514e8e87bc6a8a57a29edcb7957cdb7a65722862a61ce32f996f",
    "modules": "sha256:b624f9ba14df4da2b769b886a6675a646b29c0c430832b8b88ace6a118a1e1ac",
    "openclaw": "sha256:9fb51d4462f014dc9d86a349adafd2007d69f3f3658a0ddebffaf62451565e57",
    "protected_roots": "sha256:71012000e9e3dd48c2ce40521ca21bafff12eb61c3ce689124b11fd60c5a74a6",
    "runtime_tree": "sha256:d50dd0e151492afe35222106e0859cdecdbd200345fe2d8abfa393f5179d257b",
    "session_store": "sha256:41d4763b2f8ffa34b1b2c955352aa4415d39bb4751f4b6d6959486d66e271567",
    "target": "sha256:951685b1267f0d1b668bca18e185c5ebe95cff25b64be3146672a2e47f8fd782",
}
_STACK_DIGESTS = {
    "enablement": "sha256:2bc6ec5e27192f20dcfb2c5161ce9cf9cb8c06fdd52b8742528249c3fe8e8aaa",
    "gateway_listener": "sha256:7138b97477b417300a3b0915fd4c9d582c62b4d02efc574188105099425aaf01",
    "processes": "sha256:0c74831ef9172cbe70b1e151c8dd1f3f76da5a00f4b1e682c6df258527c898f3",
    "service_state": "sha256:36fe96871eec94aa2efcdff02bcd0097d116409eae091a3ae6a919fff206d565",
    "sockets": "sha256:7a471182a5e87f9a2eceadcf69ad0a104187f0dd33c0e9a4fd572e7be6f7164c",
    "units": "sha256:2558d0d752c872e1baae45232cff6f43e4497221d2fd13120fcda997f1809c08",
}
_ROUTE_BOOLEAN_FIELDS = {
    "abortedLastRun",
    "base_entry_present",
    "enabled",
    "enqueued",
    "entries_truncated",
    "exists",
    "explicit",
    "hasMore",
    "includeDisabled",
    "inline_prompt_present",
    "missing",
    "ok",
    "parsed",
    "present",
    "prompt_ref_present",
    "raw_is_canonical_json_lf",
    "read_only",
    "ready",
    "reasoning",
    "removed",
    "sandboxed",
    "session_id_present",
    "supportsDeveloperRole",
    "supportsStore",
    "supportsStrictMode",
    "supportsTools",
    "supportsUsageInStreaming",
    "systemSent",
    "system_sent",
    "totalNearLimit",
    "totalTokensFresh",
    "truncated",
    "warningShown",
    "watch",
    "workspaceOnly",
    "writable",
}
_LIMITATIONS = {
    "outer": [
        "OBSERVED_IS_NOT_PASS",
        "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
        "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
        "PROBE_ENTERED_EXACT_GATEWAY_MOUNT_NAMESPACE_FOR_CREDENTIAL_VISIBILITY",
        "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
        "PUBLIC_NETWORK_DENIED",
        "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
        "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
    ],
    "composition": [
        "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
        "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
        "ONE_PINNED_P3_7C_ACTIVATION_ACTION_FLOW_ONLY",
        "TWENTY_ONE_ADMISSION_ROUTES_REMAIN_NOT_TESTED",
        "ACTION_OBSERVATION_DOES_NOT_PROMOTE_ANY_ADMISSION_ROUTE",
        "FRESH_RUNTIME_PROFILE_AND_FRESH_SESSIONS_REQUIRED",
        "OPENCLAW_TEST_FAST_ABSENT",
        "PUBLIC_NETWORK_DENIED",
        "EXACT_SINGLETON_EXTERNAL_SKILL_SOURCE_ONLY",
        (
            "EXACT_PINNED_ARAGORN_TOOL_PLUGIN_READ_TOOL_WORKSPACE_AND_RESOLVED_"
            "SKILL_ROOTS_AND_LOOPBACK_PROVIDER_ONLY"
        ),
        "NO_AGGREGATE_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
    ],
    "action": [
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
        (
            "SYSCALL_CAUSATION_IS_PINNED_IMPLEMENTATION_BOUND_NOT_INDEPENDENT_"
            "ATTESTATION"
        ),
        "TRACE_PROVES_ONE_ROUTE_CONNECT_WITHOUT_RETRY_NOT_APPLICATION_SEND_COUNT",
        "VERIFIER_NOT_IMPLEMENTED",
        "RETAINED_EVIDENCE_NOT_PRODUCED",
        "RUN_01_NOT_ESTABLISHED",
        "RUN_02_NOT_ESTABLISHED",
        "PHASE_3_EXIT_NOT_ESTABLISHED",
        "EDR_CLAIM_NOT_ESTABLISHED",
        "INSTALLER_AUTHORITY_NOT_ESTABLISHED",
        "PUBLIC_RELEASE_NOT_AUTHORIZED",
    ],
}
_MODULES = {
    "cron": {
        "bytes": 33_974,
        "digest": "sha256:5b4687614137ecc59ff375c47679ba641eca20d73b20cf75e0ae6bee0afbb533",
        "path": "/runtime/lib/node_modules/openclaw/dist/cron-qc-KsHeU.js",
    },
    "cron_snapshot": {
        "bytes": 53,
        "digest": "sha256:b44d93ef82f61910088810c5f26f819ef5f3b23c3d1986223781149805d86ab6",
        "path": "/runtime/lib/node_modules/openclaw/dist/cron-snapshot.runtime.js",
    },
    "cron_snapshot_implementation": {
        "bytes": 450,
        "digest": "sha256:bdc0ebba0d83ef830af7542f70c8436decc9809195f1fd6e114e11f8e6220768",
        "path": "/runtime/lib/node_modules/openclaw/dist/cron-snapshot.runtime-DOWu3ZvS.js",
    },
    "isolated_agent": {
        "bytes": 59_535,
        "digest": "sha256:111dbe5add64d796453660fe8b5f8f8fa830716d87ecc902d2b11a0489e36610",
        "path": "/runtime/lib/node_modules/openclaw/dist/isolated-agent-knotypz1.js",
    },
    "prompt_blobs": {
        "bytes": 6_621,
        "digest": "sha256:24164fbc0679c4eb55476a0bcbd2325660f59a47577509f838c682eb516e0553",
        "path": "/runtime/lib/node_modules/openclaw/dist/skill-prompt-blobs-zJRX9N65.js",
    },
    "run_session_state": {
        "bytes": 18_238,
        "digest": "sha256:aa5dad173c4d37034c0414c72093d0492009de77ff274ba4d2f7b3d509dc3817",
        "path": "/runtime/lib/node_modules/openclaw/dist/run-session-state-r5DnSgVq.js",
    },
    "session": {
        "bytes": 5_884,
        "digest": "sha256:11800a76db678e445aebb1e3193ba089c7ae8da94d3628ba4252ff5afc09cc4e",
        "path": "/runtime/lib/node_modules/openclaw/dist/session-DhY9vRaC.js",
    },
    "session_snapshot": {
        "bytes": 3_877,
        "digest": "sha256:5ac3cf77479e9573b5326f81c5ddc7ad4e21017b6f34d3bf2612d67dc8b9f50d",
        "path": "/runtime/lib/node_modules/openclaw/dist/session-snapshot-C3iM3syv.js",
    },
    "workspace_skills": {
        "bytes": 55_215,
        "digest": "sha256:9a573db609deb917613f3e85437236a5997883daa299a52f2652891b7ec43b1b",
        "path": "/runtime/lib/node_modules/openclaw/dist/workspace-DvqxsRU0.js",
    },
}
_PROCESS_IDENTITIES = {
    "aragorn-agent-gateway.service": {
        "cmdline": ["openclaw-gateway"],
        "gids": [992, 992, 992, 992],
        "groups": [992],
        "uids": [992, 992, 992, 992],
    },
    "aragorn-runtime-action-worker.service": {
        "cmdline": [
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py",
            "/run/credentials/aragorn-runtime-action-worker.service/worker-binding",
        ],
        "gids": [997, 997, 997, 997],
        "groups": [992, 997],
        "uids": [997, 997, 997, 997],
    },
    "aragorn-runtime-lineage-capability-action-broker.service": {
        "cmdline": [
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/aragorn-runtime-action-service-v5.py",
            "/run/credentials/aragorn-runtime-lineage-capability-action-broker.service/runtime-binding",
            "/run/credentials/aragorn-runtime-lineage-capability-action-broker.service/capability-grant",
        ],
        "gids": [997, 997, 997, 997],
        "groups": [996, 997],
        "uids": [995, 995, 995, 995],
    },
    "aragorn-runtime-lineage-capability-observation-publisher.service": {
        "cmdline": [
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/aragorn-runtime-observation-service-v4.py",
            "/run/credentials/aragorn-runtime-lineage-capability-observation-publisher.service/observation-binding",
            "/run/credentials/aragorn-runtime-lineage-capability-observation-publisher.service/capability-grant",
        ],
        "gids": [996, 996, 996, 997],
        "groups": [996, 997],
        "uids": [996, 996, 996, 997],
    },
}
_SESSION_STORE = parent._SESSION_STORE


def verify_openclaw_final_combined_v2_cron_rescan(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return exact 3/21 V2 route coverage after all three semantic checks."""

    try:
        if (
            _digest(Path(parent.__file__).read_bytes()) != _PARENT_VERIFIER
            or _digest(Path(cron.__file__).read_bytes()) != _CRON_VERIFIER
        ):
            raise AdmissionEvidenceError("V2 cron parent verifier changed")
        parent_result = parent.verify_openclaw_final_combined_v2_prompt_rebuild(
            evidence_cas=evidence_cas
        )
        if _canonical_digest(parent_result) != _PARENT_DIGEST:
            raise AdmissionEvidenceError("V2 cron parent qualification changed")
        retained = _verify_retained_evidence()
        raw = parent.parent.legacy.parent._read_blob(
            evidence_cas, _EVIDENCE, "V2 cron rescan"
        )
        if raw != retained:
            raise AdmissionEvidenceError("V2 cron CAS differs from signed retention")
        evidence = parent.parent.legacy.parent._load_canonical_json(
            raw, _EVIDENCE, "V2 cron rescan"
        )
        trusted_raw = parent.parent.legacy.parent._read_blob(
            evidence_cas, parent._EVIDENCE, "V2 prompt rebuild"
        )
        trusted_evidence = parent.parent.legacy.parent._load_canonical_json(
            trusted_raw, parent._EVIDENCE, "V2 prompt rebuild"
        )
        _verify_evidence(
            evidence,
            trusted_stack=trusted_evidence["route_observation"]["stack_before"],
        )
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
        raise AdmissionEvidenceError(f"invalid V2 cron evidence: {exc}") from exc

    routes = [
        {
            "id": route["id"],
            "status": "PASS" if route["id"] in _PASS_ROUTES else "NOT_TESTED",
        }
        for route in parent_result["profile"]["routes"]
    ]
    return {
        "schema": (
            "aragorn/admission-protected-final-combined-v2-cron-rescan-route-"
            "coverage/v1"
        ),
        "assurance": "THREE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V2_ROUTES_ONLY",
        "bindings": {
            "cron_rescan_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": parent.parent.legacy.parent._SIGNATURE["key"],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_SOURCE,
                    "signature": dict(parent.parent.legacy.parent._SIGNATURE),
                },
            },
            "embedded_p3_7c_action_cases": {
                "canonical_digest": _canonical_digest(
                    evidence["composition"]["action"]["cases"]
                ),
                "semantic_input_to_cron_route_pass": False,
            },
            "image": _IMAGE,
            "legacy_cron_verifier_implementation_digest": _CRON_VERIFIER,
            "parent_qualification_canonical_digest": _PARENT_DIGEST,
            "parent_verifier_implementation_digest": _PARENT_VERIFIER,
            "source_artifacts": {
                name: dict(identity) for name, identity in _SOURCE_ARTIFACTS.items()
            },
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            **{key: False for key in parent.parent.legacy.parent._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "THREE_EXACT_DYNAMIC_ROUTE_PASSES_ONLY",
            "EIGHTEEN_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "THREE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURES_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "EMBEDDED_P3_7C_ACTION_CASES_IDENTITY_BOUND_NOT_SEMANTICALLY_REPLAYED",
            "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"PASS": 3, "NOT_TESTED": 18},
            "name": parent_result["profile"]["name"],
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [
                "ADM-02/reload/fresh-session-reset",
                "ADM-02/reload/missing-prompt-blob-rebuild",
                _ROUTE,
            ],
            "pass_basis": [
                "SIGNED_EXACT_RESET_ROTATION_CLEAR_AND_REBUILD_TRANSITION",
                "SIGNED_EXACT_PROMPT_BLOB_UNLINK_AND_RECONSTRUCTION_TRANSITION",
                "SIGNED_EXACT_CRON_FORCE_RUN_SNAPSHOT_AND_MODEL_NOT_FOUND_TRANSITION",
            ],
            "transitions_dynamically_exercised": True,
            "excluded_semantic_inputs": ["embedded_p3_7c_action_cases"],
        },
        "runtime": dict(parent_result["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_digest(value: Mapping[str, Any]) -> str:
    return _digest(
        parent.parent.legacy.parent.oci_worker_protocol.canonical_json(value)
    )


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    git = parent.parent.legacy._git
    if (
        Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(
            strict=True
        )
        != root
        or git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V2 cron signed repository changed")
    parent.parent._verify_commit(_SOURCE)
    parent.parent._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V2 cron signed tree entry changed")
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=640 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V2 cron signed blob changed")
    return raw


def _verify_evidence(
    evidence: Mapping[str, Any], *, trusted_stack: Mapping[str, Any]
) -> None:
    _verify_no_unexpected_floats(evidence)
    _verify_no_positive_eligibility(evidence)
    expected_decision = {
        "status": "FINAL_COMBINED_V2_ROUTE_OBSERVED_PROFILE_NOT_TESTED",
        "route_observation_status": "OBSERVED",
        "route_pass_count": 0,
        "route_fail_count": 0,
        "route_not_tested_count": 21,
        **{key: False for key in parent.parent.legacy.parent._ELIGIBILITY_KEYS},
    }
    if (
        set(evidence)
        != {
            "authority",
            "composition",
            "decision",
            "limitations",
            "recorded_at",
            "route_id",
            "route_observation",
            "schema",
            "source_artifacts",
        }
        or evidence["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-route-systemd-observation/v1"
        or evidence["route_id"] != _ROUTE
        or evidence["recorded_at"] != "2026-08-22T07:00:24.289070Z"
        or evidence["authority"]
        != (
            "BOUND_FINAL_COMBINED_V2_RAW_ROUTE_OBSERVATION_ONLY_NOT_ADMISSION_"
            "RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            evidence["decision"]
        )
        != parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            expected_decision
        )
        or any(
            type(evidence["decision"][field]) is not int
            for field in (
                "route_fail_count",
                "route_not_tested_count",
                "route_pass_count",
            )
        )
        or evidence["limitations"] != _LIMITATIONS["outer"]
    ):
        raise AdmissionEvidenceError("V2 cron wrapper changed")
    composition = evidence["composition"]
    profile_before = composition["profile"]["before"]
    profile_after = composition["profile"]["after"]
    profile = profile_after["document"]
    action_envelope = composition["action"]
    source = action_envelope["artifacts"]["final_combined_v2"]
    harness = action_envelope["harness"]["document"]
    lineage = harness["image_lineage"]
    runtime_volume = parent.parent.legacy.parent._RUNTIME["runtime_volume"]
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
        != "aragorn/runtime-action-worker-final-combined-v2-systemd-observation/v1"
        or composition["recorded_at"] != "2026-08-22T07:00:24.289050Z"
        or composition["authority"]
        != (
            "BOUNDED_FINAL_COMBINED_V2_P3_7C_ACTION_OBSERVATION_ONLY_PROFILE_"
            "ROUTES_REMAIN_NOT_TESTED_NOT_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            composition["decision"]
        )
        != parent.parent.legacy.parent.oci_worker_protocol.canonical_json({
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
            "status": "FINAL_COMBINED_V2_ACTION_OBSERVED_PROFILE_NOT_TESTED",
        })
        or any(
            type(composition["decision"][field]) is not int
            for field in (
                "route_fail_count",
                "route_not_tested_count",
                "route_pass_count",
            )
        )
        or composition["limitations"] != _LIMITATIONS["composition"]
        or set(action_envelope)
        != {
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
        or _canonical_digest(action_envelope) != _COMPOSITION_ACTION_DIGEST
        or action_envelope["schema"]
        != "aragorn/runtime-action-worker-activation-expiry-systemd-observation/v1"
        or action_envelope["recorded_at"] != "2026-08-22T07:00:23.950284Z"
        or action_envelope["authority"]
        != (
            "BOUNDED_ACTIVATION_EXPIRY_ROTATION_OBSERVATION_ONLY_NOT_VERIFIED_"
            "RUN_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            action_envelope["decision"]
        )
        != parent.parent.legacy.parent.oci_worker_protocol.canonical_json({
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
        })
        or action_envelope["limitations"] != _LIMITATIONS["action"]
        or set(action_envelope["cases"])
        != {
            "coherent_consumed",
            "expired_fail_stop",
            "full_activation",
            "terminal_archive_rotation",
        }
        or parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            action_envelope["secret_checks"]
        )
        != parent.parent.legacy.parent.oci_worker_protocol.canonical_json({
            "forbidden_driver_fields": [],
            "gateway_environment_bytes_retained": False,
            "gateway_environment_digest_retained": False,
            "provider_and_gateway_token_values_retained": False,
        })
        or parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            profile_before
        )
        != parent.parent.legacy.parent.oci_worker_protocol.canonical_json(profile_after)
        or parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            profile_before
        )
        != parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            source["profile"]
        )
        or parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            action_envelope["inputs"]["gateway_config"]
        )
        != parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            source["config"]["document"]
        )
        or profile["name"] != parent.parent._PROFILE
        or [route["id"] for route in profile["routes"]]
        != list(parent.parent.legacy.parent._ROUTES)
        or profile_after["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or any(type(value) is not int for value in profile_after["outcomes"].values())
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or harness["source_commit"] != _SOURCE["commit"]
        or set(harness)
        != {
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
            "route_input_mount",
            "route_input_volume_identity",
            "run_image_reference",
            "schema",
            "source_commit",
            "source_commit_verification",
        }
        or _canonical_digest(harness) != _HARNESS_DIGEST
        or harness["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-systemd-harness/v1"
        or harness["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or harness["image_reference"]
        != "aragorn-phase3-final-combined-v2-systemd"
        or harness["platform"] != "linux"
        or harness["profile_label"] != "phase3-final-combined-v2"
        or harness["image_id"] != _IMAGE
        or harness["run_image_reference"] != _IMAGE
        or harness["parent_image_id"] != parent.parent._PARENT_IMAGE
        or lineage["child"]["id"] != _IMAGE
        or lineage["parent"]["id"] != parent.parent._PARENT_IMAGE
        or _canonical_digest(lineage) != _IMAGE_LINEAGE_DIGEST
        or not lineage["added_layers"]
        or lineage["child"]["layers"]
        != lineage["parent"]["layers"] + lineage["added_layers"]
        or lineage["child"]["rootfs_type"] != "layers"
        or lineage["parent"]["rootfs_type"] != "layers"
        or _canonical_digest(harness["host_config"]) != _HOST_CONFIG_DIGEST
        or harness["host_config"]["privileged"] is not True
        or harness["host_config"]["readonly_rootfs"] is not False
        or harness["host_config"]
        != {
            "binds": [
                "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                f"{runtime_volume}:/runtime:ro",
                f"{_ROUTE_VOLUME}:/route-input:ro",
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
        or harness["openclaw_runtime_mount"]
        != {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": runtime_volume,
            "type": "volume",
        }
        or harness["openclaw_runtime_mount"]["rw"] is not False
        or harness["openclaw_runtime_volume"] != runtime_volume
        or harness["openclaw_runtime_volume_identity"]
        != {
            "driver": "local",
            "labels": {
                "io.aragorn.phase": "phase3-final",
                "io.aragorn.role": "installed-runtime",
                "io.aragorn.source-commit": parent.parent.legacy.parent._OPENCLAW[
                    "commit"
                ],
                "io.aragorn.source-tree": parent.parent.legacy.parent._OPENCLAW[
                    "source_tree"
                ],
            },
            "name": runtime_volume,
            "options": None,
            "scope": "local",
        }
        or harness["route_input_mount"]
        != {
            "destination": "/route-input",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": _ROUTE_VOLUME,
            "type": "volume",
        }
        or harness["route_input_mount"]["rw"] is not False
        or harness["route_input_volume_identity"]
        != {
            "driver": "local",
            "labels": {
                "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:64792",
                "dev.aragorn.role": "final-combined-v2-route-input",
                "dev.aragorn.source-commit": _SOURCE["commit"],
            },
            "name": _ROUTE_VOLUME,
            "options": None,
            "scope": "local",
        }
        or action_envelope["runtime"]
        != {
            "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "entrypoint_digest": parent.parent.legacy.parent._RUNTIME[
                "entrypoint_digest"
            ],
            "expected_version": parent.parent.legacy.parent._RUNTIME["version_output"],
            "root": "/runtime",
            "tree": parent.parent.legacy.parent._RUNTIME_TREE,
            "version_output": parent.parent.legacy.parent._RUNTIME["version_output"],
        }
        or composition["bindings"]
        != {
            "config_materialization": "canonical_json_without_trailing_lf",
            "network": "none",
            "openclaw_test_fast": "absent",
            "runtime_digest": parent.parent.legacy.parent._RUNTIME["runtime_digest"],
            "runtime_volume": runtime_volume,
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": parent.parent._SOURCES["skill"]["digest"],
        }
        or set(harness["source_commit_verification"])
        != {"command", "commit_object", "exit_code", "stderr", "stdout"}
        or harness["source_commit_verification"]["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or type(harness["source_commit_verification"]["exit_code"]) is not int
        or harness["source_commit_verification"]["exit_code"] != 0
    ):
        raise AdmissionEvidenceError("V2 cron profile or harness changed")
    parent.parent._verify_source_file(
        source["config"]["file"], parent.parent._SOURCES["configuration"]
    )
    parent.parent._verify_source_file(
        source["profile"]["file"], parent.parent._SOURCES["profile"]
    )
    parent.parent._verify_source_file(
        source["runtime_lock"]["file"], parent.parent._SOURCES["runtime_lock"]
    )
    parent.parent._verify_file(source["skill"]["file"], parent.parent._SOURCES["skill"])
    if any(
        parent.parent.legacy._canonical_digest(source[name]["document"])
        != parent.parent._SOURCES[label]["canonical_digest"]
        for name, label in (
            ("config", "configuration"),
            ("profile", "profile"),
            ("runtime_lock", "runtime_lock"),
        )
    ):
        raise AdmissionEvidenceError("V2 cron embedded source document changed")
    for name, identity in parent.parent._PLUGIN.items():
        parent.parent._verify_file(source["plugin"][name], identity)
    if set(evidence["source_artifacts"]) != {
        "collector",
        "materializer",
        "probe_bundle",
        "v1_route_injector",
    }:
        raise AdmissionEvidenceError("V2 cron source-artifact envelope changed")
    source_paths = {
        "collector": (
            "/src/scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py"
        ),
        "materializer": "/src/scripts/materialize_fixed_admission_probes.py",
        "v1_route_injector": (
            "/src/scripts/runtime_action_worker_final_route_systemd_probe.py"
        ),
    }
    source_files = []
    for name, path in source_paths.items():
        source_files.append(
            _verify_source_file(
                evidence["source_artifacts"][name],
                _SOURCE_ARTIFACTS[name],
                path=path,
            )
        )
    if (
        len({stat["inode"] for stat in source_files}) != len(source_files)
        or len({stat["device"] for stat in source_files}) != 1
    ):
        raise AdmissionEvidenceError("V2 cron source artifact custody changed")
    bundle = evidence["source_artifacts"]["probe_bundle"]
    if bundle != [
        {**_SOURCE_ARTIFACTS["probe"], "name": "protected-cron-rescan-probe.mjs"},
        {**_SOURCE_ARTIFACTS["helper"], "name": "protected-observation-v1.mjs"},
    ] or any(type(item["bytes"]) is not int for item in bundle):
        raise AdmissionEvidenceError("V2 cron probe bundle changed")
    observation = evidence["route_observation"]
    _verify_route_scalar_types(observation)
    document = _decode_route_raw(observation["raw"])
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
        or parent.parent.legacy.parent.oci_worker_protocol.canonical_json(document)
        != parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            observation["document"]
        )
        or parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            observation["route"]
        )
        != parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            document["route"]
        )
        or observation["bundle"] != bundle
    ):
        raise AdmissionEvidenceError("V2 cron nested custody changed")
    _verify_execution(
        observation,
        action_envelope["boundaries"],
        harness["container_id"],
        trusted_stack,
    )
    if not (
        parent.parent.legacy._parse_time(document["recorded_at"])
        <= parent.parent.legacy._parse_time(observation["execution"]["completed_at"])
        <= parent.parent.legacy._parse_time(action_envelope["recorded_at"])
        <= parent.parent.legacy._parse_time(composition["recorded_at"])
        <= parent.parent.legacy._parse_time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("V2 cron execution custody changed")
    _verify_cron(document, harness["container_id"], evidence["recorded_at"])


def _verify_no_positive_eligibility(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and key.endswith("_eligible") and item is not False:
                raise AdmissionEvidenceError("V2 cron positive eligibility claim")
            _verify_no_positive_eligibility(item)
    elif isinstance(value, list):
        for item in value:
            _verify_no_positive_eligibility(item)


def _verify_no_unexpected_floats(value: Any, *, allowed: bool = False) -> None:
    if type(value) is float:
        if not allowed:
            raise AdmissionEvidenceError("V2 cron unexpected floating-point value")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _verify_no_unexpected_floats(
                item, allowed=isinstance(key, str) and key == "loadAverage"
            )
    elif isinstance(value, list):
        for item in value:
            _verify_no_unexpected_floats(item, allowed=allowed)


def _verify_route_scalar_types(value: Any, *, float_allowed: bool = False) -> None:
    if type(value) is float:
        if not float_allowed:
            raise AdmissionEvidenceError("V2 cron unexpected floating-point value")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and (
                (key in _ROUTE_BOOLEAN_FIELDS) != (type(item) is bool)
            ):
                raise AdmissionEvidenceError("V2 cron boolean field type changed")
            _verify_route_scalar_types(
                item,
                float_allowed=isinstance(key, str) and key == "loadAverage",
            )
    elif isinstance(value, list):
        for item in value:
            if type(item) is bool:
                raise AdmissionEvidenceError("V2 cron boolean list item changed")
            _verify_route_scalar_types(item, float_allowed=float_allowed)


def _verify_source_file(
    value: Mapping[str, Any], expected: Mapping[str, Any], *, path: str
) -> Mapping[str, Any]:
    parent.parent._verify_file(value, expected)
    stat = value["stat"]
    if (
        set(value) != {"bytes", "digest", "path", "stat"}
        or value["path"] != path
        or type(value["bytes"]) is not int
        or set(stat)
        != {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
        or any(type(stat[field]) is not int for field in ("device", "inode"))
        or stat["device"] <= 0
        or stat["inode"] <= 0
        or type(stat["gid"]) is not int
        or stat["gid"] != 0
        or type(stat["uid"]) is not int
        or stat["uid"] != 0
        or stat["mode"] != "0555"
        or type(stat["nlink"]) is not int
        or stat["nlink"] != 1
        or type(stat["size"]) is not int
        or stat["size"] != value["bytes"]
        or stat["type"] != "file"
    ):
        raise AdmissionEvidenceError("V2 cron source artifact changed")
    return stat


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(value) != {
        "base64",
        "bytes",
        "canonical_digest",
        "digest",
        "raw_is_canonical_json_lf",
    }:
        raise AdmissionEvidenceError("V2 cron raw envelope changed")
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(
        raw.decode(),
        object_pairs_hook=parent.parent.legacy.parent._reject_duplicates,
        parse_constant=parent.parent.legacy.parent._reject_constant,
    )
    canonical = parent.parent.legacy.parent.oci_worker_protocol.canonical_json(document)
    if (
        raw != canonical + b"\n"
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
        or value["canonical_digest"] != _digest(canonical)
        or value["raw_is_canonical_json_lf"] is not True
    ):
        raise AdmissionEvidenceError("V2 cron raw identity changed")
    _verify_route_scalar_types(document)
    return document


def _verify_execution(
    observation: Mapping[str, Any],
    boundaries: Mapping[str, Any],
    container_id: str,
    trusted_stack: Mapping[str, Any],
) -> None:
    execution = observation["execution"]
    binding = observation["gateway_pid_binding"]
    document = observation["document"]
    stack = observation["stack_before"]
    units = stack["units"]
    gateway_unit = "aragorn-agent-gateway.service"
    pid = binding["pid"]
    unit_names = {
        gateway_unit,
        "aragorn-runtime-action-worker.service",
        "aragorn-runtime-lineage-capability-action-broker.service",
        "aragorn-runtime-lineage-capability-observation-publisher.service",
    }
    process = stack["processes"][gateway_unit]
    nested = document["action"]["prerequisites"]["gateway_process_before"]
    if (
        set(execution)
        != {
            "argv",
            "completed_at",
            "effective_identity",
            "environment_names",
            "exit_code",
            "started_at",
            "stderr",
        }
        or set(binding) != {"environment_name", "mount_namespace", "pid", "unit"}
        or not isinstance(container_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        or not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 0
        or binding
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{pid}/ns/mnt",
            "pid": pid,
            "unit": gateway_unit,
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
            "/route-input/cron-rescan/protected-cron-rescan-probe.mjs",
        ]
        or execution["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or any(
            type(identity) is not int
            for identity in (
                execution["effective_identity"]["gid"],
                execution["effective_identity"]["uid"],
                *execution["effective_identity"]["groups"],
            )
        )
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
        or type(execution["exit_code"]) is not int
        or execution["exit_code"] != 0
        or execution["stderr"] != {"bytes": 0, "digest": _digest(b""), "excerpt": ""}
        or set(stack)
        != {
            "enablement",
            "gateway_listener",
            "pids",
            "processes",
            "service_state",
            "sockets",
            "units",
        }
        or set(boundaries)
        != {
            "activation_lock",
            "enablement",
            "gateway_listener",
            "processes",
            "service_state",
            "sockets",
            "units",
        }
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
            _canonical_digest(stack[name]) != digest
            or _canonical_digest(boundaries[name]) != digest
            for name, digest in _STACK_DIGESTS.items()
        )
        or set(units) != unit_names
        or set(stack["pids"]) != unit_names
        or set(stack["processes"]) != unit_names
        or set(stack["enablement"]) != unit_names
        or set(stack["service_state"]) != {"sockets", "units"}
        or set(stack["service_state"]["units"]) != unit_names
        or stack["pids"][gateway_unit] != pid
        or stack["gateway_listener"]["pid"] != pid
        or process["pid"] != pid
        or type(process["pid"]) is not int
        or process["cmdline"] != ["openclaw-gateway"]
        or process["uids"] != [992, 992, 992, 992]
        or process["gids"] != [992, 992, 992, 992]
        or process["groups"] != [992]
        or process["capabilities_effective"] != "0000000000000000"
        or type(process["no_new_privileges"]) is not int
        or process["no_new_privileges"] != 1
        or nested["pid"] != pid
        or type(nested["pid"]) is not int
        or nested["hostname"] != container_id[:12]
        or nested["cmdline"] != process["cmdline"]
        or nested["start_time_ticks"] != process["start_time_ticks"]
        or nested["effective_capabilities"] != process["capabilities_effective"]
        or nested["no_new_privileges"] != str(process["no_new_privileges"])
        or not (
            parent.parent.legacy._parse_time(execution["started_at"])
            <= parent.parent.legacy._parse_time(
                document["action"]["commands"][0]["started_at"]
            )
            <= parent.parent.legacy._parse_time(document["recorded_at"])
            <= parent.parent.legacy._parse_time(execution["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("V2 cron execution boundary changed")
    parent.parent.legacy._verify_stack_boundary(
        stack,
        trusted=trusted_stack,
        container_id=container_id,
        snapshot_before=execution["started_at"],
    )
    parent.parent.legacy._verify_gateway_listener(
        stack["gateway_listener"], stack["processes"]
    )
    execution_started = parent.parent.legacy._parse_time(execution["started_at"])
    invocation_ids: set[str] = set()
    for name in unit_names:
        expected_cgroup = f"/docker/{container_id}/system.slice/{name}"
        unit = units[name]
        service = stack["service_state"]["units"][name]
        properties = service["properties"]
        service_process = stack["processes"][name]
        service_pid = stack["pids"][name]
        command = service["command"]
        if (
            not isinstance(service_pid, int)
            or isinstance(service_pid, bool)
            or service_pid <= 0
            or service_process["pid"] != service_pid
            or type(service_process["pid"]) is not int
            or unit["MainPID"] != str(service_pid)
            or properties["MainPID"] != str(service_pid)
            or service["cgroup_members"] != [str(service_pid)]
            or unit["ActiveState"] != "active"
            or unit["SubState"] != "running"
            or unit["Result"] != "success"
            or properties["ActiveState"] != "active"
            or properties["SubState"] != "running"
            or properties["Result"] != "success"
            or unit["ControlGroup"] != expected_cgroup
            or properties["ControlGroup"] != expected_cgroup
            or properties["UnitFileState"] != stack["enablement"][name]
            or not isinstance(properties["InvocationID"], str)
            or re.fullmatch(r"[0-9a-f]{32}", properties["InvocationID"]) is None
            or int(properties["ActiveEnterTimestampMonotonic"])
            < int(properties["ExecMainStartTimestampMonotonic"])
            or int(properties["ActiveEnterTimestampMonotonic"]) * 1_000
            > command["completed_monotonic_ns"]
            or {
                field: service_process[field]
                for field in ("cmdline", "gids", "groups", "uids")
            }
            != _PROCESS_IDENTITIES[name]
            or any(
                type(identity) is not int
                for field in ("gids", "groups", "uids")
                for identity in service_process[field]
            )
            or service_process["capabilities_effective"] != "0000000000000000"
            or type(service_process["no_new_privileges"]) is not int
            or service_process["no_new_privileges"] != 1
            or re.fullmatch(r"mnt:\[[1-9][0-9]*\]", service_process["mount_namespace"])
            is None
            or re.fullmatch(
                r"net:\[[1-9][0-9]*\]", service_process["network_namespace"]
            )
            is None
            or not isinstance(service_process["start_time_ticks"], str)
            or re.fullmatch(r"[1-9][0-9]*", service_process["start_time_ticks"]) is None
            or abs(
                int(properties["ExecMainStartTimestampMonotonic"])
                - int(service_process["start_time_ticks"]) * 10_000
            )
            >= 30_000
            or not (
                parent.parent.legacy._parse_time(command["started_at"])
                <= parent.parent.legacy._parse_time(command["completed_at"])
                <= execution_started
            )
        ):
            raise AdmissionEvidenceError(f"V2 cron service boundary changed: {name}")
        invocation_ids.add(properties["InvocationID"])
        parent.parent.legacy._verify_service_command(command, properties)
    if len(invocation_ids) != len(unit_names):
        raise AdmissionEvidenceError("V2 cron service invocation reused")
    if len(set(stack["pids"].values())) != len(unit_names):
        raise AdmissionEvidenceError("V2 cron service PID reused")
    if set(stack["pids"].values()) & {
        command["pid"] for command in document["action"]["commands"]
    }:
        raise AdmissionEvidenceError("V2 cron command reused a service PID")
    if any(
        len({process[field] for process in stack["processes"].values()})
        != len(unit_names)
        for field in ("mount_namespace", "network_namespace")
    ):
        raise AdmissionEvidenceError("V2 cron service namespace reused")


def _verify_cron(
    document: Mapping[str, Any], container_id: str, outer_recorded_at: str
) -> None:
    if (
        set(document)
        != {
            "action",
            "assurance",
            "implementation_digests",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
        or set(document["action"])
        != {
            "commands",
            "execution_error",
            "id",
            "observations",
            "prerequisites",
            "reason_codes",
            "status",
        }
        or set(document["action"]["prerequisites"])
        != {
            "boundary_before",
            "config_before",
            "config_lock_before",
            "config_tree_before",
            "cron_inventory_before",
            "gateway_process_before",
            "module_files_before",
            "openclaw_before",
            "protected_root_trees_before",
            "runtime_tree_before",
            "session_store_before",
            "system_info_before",
            "target_before",
            "version",
        }
        or set(document["action"]["observations"])
        != {
            "boundary_after",
            "cleanup",
            "config_after",
            "config_lock_after",
            "config_tree_after",
            "cron_inventory_after_add",
            "cron_inventory_after_remove",
            "gateway_process_after",
            "job",
            "module_files_after",
            "openclaw_after",
            "protected_root_trees_after",
            "run",
            "runtime_tree_after",
            "session_state_before_forced_run",
            "session_store_after",
            "snapshot",
            "system_info_after",
            "target_after",
            "terminal_result",
        }
        or document["schema"] != "aragorn/openclaw-protected-cron-rescan-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digests"]
        != {
            "helper": _SOURCE_ARTIFACTS["helper"]["digest"],
            "probe": _SOURCE_ARTIFACTS["probe"]["digest"],
        }
        or document["runtime_binding"]
        != {
            "commit": parent.parent.legacy.parent._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": parent.parent.legacy.parent._RUNTIME[
                "entrypoint_digest"
            ],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": parent.parent.legacy.parent._RUNTIME_TREE[
                "tree_digest"
            ],
            "version": parent.parent.legacy.parent._OPENCLAW["version"],
        }
        or document["route"]
        != {
            "action_id": "cron-rescan",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
        or _canonical_digest(document["action"]) != _ACTION_DIGEST
    ):
        raise AdmissionEvidenceError("V2 cron observation identity changed")
    action = document["action"]
    before = action["prerequisites"]
    after = action["observations"]
    stable = (
        (before["boundary_before"], after["boundary_after"], "boundary"),
        (before["config_before"], after["config_after"], "config"),
        (before["config_lock_before"], after["config_lock_after"], None),
        (before["config_tree_before"], after["config_tree_after"], "config_tree"),
        (
            before["protected_root_trees_before"],
            after["protected_root_trees_after"],
            "protected_roots",
        ),
        (before["target_before"], after["target_after"], "target"),
        (before["runtime_tree_before"], after["runtime_tree_after"], "runtime_tree"),
        (before["openclaw_before"], after["openclaw_after"], "openclaw"),
        (before["gateway_process_before"], after["gateway_process_after"], "gateway"),
        (before["module_files_before"], after["module_files_after"], "modules"),
    )
    if (
        action["id"] != "cron-rescan"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or any(left != right for left, right, _ in stable)
        or any(
            name is not None and _canonical_digest(left) != _STATIC_DIGESTS[name]
            for left, _right, name in stable
        )
    ):
        raise AdmissionEvidenceError("V2 cron protected state changed")
    _verify_static(before, container_id)
    _verify_route(
        action,
        document["recorded_at"],
        expected_gateway_pid=before["gateway_process_before"]["pid"],
        expected_hostname=before["gateway_process_before"]["hostname"],
    )
    if parent.parent.legacy._parse_time(
        document["recorded_at"]
    ) >= parent.parent.legacy._parse_time(outer_recorded_at):
        raise AdmissionEvidenceError("V2 cron recording order changed")


def _verify_static(before: Mapping[str, Any], container_id: str) -> None:
    boundary = before["boundary_before"]
    config = boundary["configuration"]
    gateway = before["gateway_process_before"]
    target = before["target_before"]
    parent._verify_read_only_mount(
        boundary["runtime"],
        target="/runtime",
        root=(
            f"/docker/volumes/{parent.parent.legacy.parent._RUNTIME['runtime_volume']}/_data"
        ),
        entries=["bin", "lib"],
        mode="755",
        nlink=4,
    )
    parent._verify_read_only_mount(
        boundary["probe"],
        target="/route-input",
        root=f"/docker/volumes/{_ROUTE_VOLUME}/_data",
        entries=[
            "cron-rescan",
            "fresh-session-reset",
            "missing-prompt-blob-rebuild",
            "session-snapshot-consumer",
        ],
        mode="555",
        nlink=6,
    )
    root_paths = {
        "extensions": "/var/lib/aragorn-agent-gateway/state/extensions",
        "managed_skills": "/var/lib/aragorn-agent-gateway/state/skills",
        "personal_agents": "/var/lib/aragorn-agent-gateway/home/.agents/skills",
        "plugin_skills": "/var/lib/aragorn-agent-gateway/state/plugin-skills",
        "project_agents": "/var/lib/aragorn-agent-gateway/workspace/.agents/skills",
        "workspace_skills": "/var/lib/aragorn-agent-gateway/workspace/skills",
    }
    if set(boundary["roots"]) != set(root_paths):
        raise AdmissionEvidenceError("V2 cron protected roots changed")
    for name, path in root_paths.items():
        value = boundary["roots"][name]
        observation = value["observation"]
        if (
            value["ready"] is not True
            or value["writable"] is not True
            or observation["path"] != path
            or observation["exists"] is not True
            or observation["type"] != "directory"
            or observation["uid"] != 992
            or observation["gid"] != 992
            or observation["mode"] != "700"
            or observation["nlink"] != 2
            or observation["entries"] != []
            or observation["entry_count"] != 0
            or observation["entries_truncated"] is not False
        ):
            raise AdmissionEvidenceError("V2 cron protected roots changed")
    config_mount = config["mount"]
    config_entry = config_mount["entry"]
    config_file = config["file"]
    session_store = before["session_store_before"]
    target_root = target["root"]
    target_file = target["entries"][0]
    if (
        _canonical_digest(boundary) != _STATIC_DIGESTS["boundary"]
        or boundary["ready"] is not True
        or boundary["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or any(
            type(identity) is not int
            for identity in (
                boundary["effective_identity"]["gid"],
                boundary["effective_identity"]["uid"],
                *boundary["effective_identity"]["groups"],
            )
        )
        or before["config_before"] != config
        or config["canonical_digest"]
        != parent.parent._SOURCES["configuration"]["canonical_digest"]
        or _canonical_digest(config["document"])
        != parent.parent._SOURCES["configuration"]["canonical_digest"]
        or config_file["digest"]
        != parent.parent._SOURCES["configuration"]["canonical_digest"]
        or config_file["path"]
        != "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
        or config_file["exists"] is not True
        or config_file["type"] != "file"
        or config_file["digest_error"] is not None
        or config_file["size"]
        != parent.parent._SOURCES["configuration"]["canonical_bytes"]
        or config_file["uid"] != 992
        or config_file["gid"] != 0
        or config_file["mode"] != "400"
        or config_file["nlink"] != 1
        or config_mount["path"] != "/run/credentials/aragorn-agent-gateway.service"
        or config_mount["explicit"] is not True
        or config_mount["read_only"] is not True
        or config_mount["ready"] is not True
        or config_mount["error"] is not None
        or config_mount["records"]
        != [
            {
                "filesystem": "ramfs",
                "mount_options": ["nodev", "noexec", "nosuid", "relatime", "ro"],
                "mount_point": "/run/credentials/aragorn-agent-gateway.service",
                "root": "/",
                "source": "ramfs",
                "super_options": ["mode=700", "rw"],
            }
        ]
        or config_entry["path"] != "/run/credentials/aragorn-agent-gateway.service"
        or config_entry["exists"] is not True
        or config_entry["type"] != "directory"
        or config_entry["uid"] != 992
        or config_entry["gid"] != 0
        or config_entry["mode"] != "500"
        or config_entry["nlink"] != 2
        or config_entry["entries"] != ["openclaw-config"]
        or config_entry["entry_count"] != 1
        or config_entry["entries_truncated"] is not False
        or before["runtime_tree_before"] != parent.parent.legacy.parent._RUNTIME_TREE
        or before["config_lock_before"]
        != {
            "exists": False,
            "path": "/run/credentials/aragorn-agent-gateway.service/openclaw-config.lock",
        }
        or _canonical_digest(before["session_store_before"])
        != _STATIC_DIGESTS["session_store"]
        or set(session_store)
        != {
            "device",
            "digest",
            "digest_error",
            "exists",
            "gid",
            "inode",
            "mode",
            "nlink",
            "path",
            "size",
            "type",
            "uid",
        }
        or session_store["path"] != _SESSION_STORE
        or session_store["exists"] is not True
        or session_store["type"] != "file"
        or session_store["uid"] != 992
        or session_store["gid"] != 992
        or session_store["mode"] != "600"
        or session_store["nlink"] != 1
        or any(
            not isinstance(session_store[field], int)
            or isinstance(session_store[field], bool)
            or session_store[field] <= 0
            for field in ("device", "inode")
        )
        or not isinstance(session_store["size"], int)
        or isinstance(session_store["size"], bool)
        or session_store["size"] <= 0
        or re.fullmatch(r"sha256:[0-9a-f]{64}", session_store["digest"]) is None
        or session_store["digest_error"] is not None
        or target["tree_digest"]
        != "sha256:38625b40892cc1f5b3cac1dcc6cd0116f8b7f21900a5baa7eeeded0ed2e87ed1"
        or target["ready"] is not True
        or len(target["entries"]) != 1
        or target_root["path"] != "/opt/aragorn/runtime-profile/template-skill"
        or target_root["exists"] is not True
        or target_root["type"] != "directory"
        or target_root["uid"] != 0
        or target_root["gid"] != 0
        or target_root["mode"] != "555"
        or target_root["nlink"] != 2
        or target_root["entries"] != ["SKILL.md"]
        or target_root["entry_count"] != 1
        or target_root["entries_truncated"] is not False
        or target_file["path"] != "SKILL.md"
        or target_file["exists"] is not True
        or target_file["type"] != "file"
        or target_file["digest"] != parent.parent._SOURCES["skill"]["digest"]
        or target_file["digest_error"] is not None
        or target_file["size"] != parent.parent._SOURCES["skill"]["bytes"]
        or target_file["uid"] != 0
        or target_file["gid"] != 0
        or target_file["mode"] != "444"
        or target_file["nlink"] != 1
        or gateway["pid"] != 2745
        or gateway["hostname"] != container_id[:12]
        or gateway["cmdline"] != ["openclaw-gateway"]
        or gateway["effective_capabilities"] != "0000000000000000"
        or gateway["no_new_privileges"] != "1"
        or gateway["seccomp"] != "2"
        or before["openclaw_before"]["digest"]
        != parent.parent.legacy.parent._RUNTIME["entrypoint_digest"]
    ):
        raise AdmissionEvidenceError("V2 cron static boundary changed")
    modules = before["module_files_before"]
    if set(modules) != set(_MODULES):
        raise AdmissionEvidenceError("V2 cron runtime module inventory changed")
    for name, identity in _MODULES.items():
        value = modules[name]
        expected = value["expected"]
        observed = value["observed"]
        if (
            expected != identity
            or observed["path"] != identity["path"]
            or observed["size"] != identity["bytes"]
            or observed["digest"] != identity["digest"]
            or observed["exists"] is not True
            or observed["type"] != "file"
            or observed["uid"] != 0
            or observed["gid"] != 0
            or observed["mode"] != "644"
            or observed["nlink"] != 1
            or observed["digest_error"] is not None
        ):
            raise AdmissionEvidenceError("V2 cron runtime module changed")


def _verify_route(
    action: Mapping[str, Any],
    recorded_at: str,
    *,
    expected_gateway_pid: int,
    expected_hostname: str,
) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    _verify_version(before["version"])
    _verify_system(
        before["system_info_before"], expected_gateway_pid, expected_hostname
    )
    _verify_system(after["system_info_after"], expected_gateway_pid, expected_hostname)
    system_before = before["system_info_before"]["response"]["value"]
    system_after = after["system_info_after"]["response"]["value"]
    if any(
        system_before[field] != system_after[field]
        for field in (
            "arch",
            "cpuCount",
            "diskPath",
            "diskTotalBytes",
            "hostname",
            "machineName",
            "memoryTotalBytes",
            "nodeVersion",
            "osLabel",
            "pid",
            "platform",
            "port",
            "release",
        )
    ):
        raise AdmissionEvidenceError("V2 cron system identity drifted")
    if system_after["uptimeMs"] < system_before["uptimeMs"]:
        raise AdmissionEvidenceError("V2 cron system uptime regressed")
    inventory_before = _verify_cron_inventory(
        before["cron_inventory_before"],
        mtime_not_after=after["job"]["command"]["started_at"],
    )
    job_id = _verify_job(after["job"])
    job = after["job"]["response"]["value"]
    inventory_after_add = _verify_cron_inventory(
        after["cron_inventory_after_add"],
        job=job,
        mtime_not_before=after["job"]["command"]["started_at"],
        mtime_not_after=after["session_state_before_forced_run"]["started_at"],
    )
    pre_store_document = _verify_pre_run(
        after["session_state_before_forced_run"],
        before["session_store_before"],
        job_id,
    )
    request = after["run"]["request"]
    _verify_native_call(
        request, method="cron.run", params={"id": job_id, "mode": "force"}
    )
    run_id = request["response"]["value"].get("runId")
    if (
        request["response"]["value"] != {"enqueued": True, "ok": True, "runId": run_id}
        or not isinstance(run_id, str)
        or cron._RUN_ID.fullmatch(run_id) is None
        or type(after["run"]["poll_count"]) is not int
        or after["run"]["poll_count"] != 1
        or after["run"]["polls"] != [after["run"]["terminal_poll"]]
    ):
        raise AdmissionEvidenceError("V2 cron forced run changed")
    poll = after["run"]["terminal_poll"]
    _verify_native_call(poll, method="cron.runs", params={"id": job_id, "limit": 10})
    terminal = after["terminal_result"]
    if poll["response"]["value"] != {
        "entries": [terminal],
        "hasMore": False,
        "limit": 10,
        "nextOffset": None,
        "offset": 0,
        "total": 1,
    }:
        raise AdmissionEvidenceError("V2 cron terminal history changed")
    _verify_snapshot(after["snapshot"], job_id, pre_store_document)
    _verify_terminal(
        terminal,
        job=after["job"],
        request=request,
        poll=poll,
        snapshot=after["snapshot"],
        job_id=job_id,
        run_id=run_id,
    )
    _verify_store(
        after["session_store_after"],
        after["snapshot"]["store"],
        before["session_store_before"],
    )
    _verify_native_call(after["cleanup"], method="cron.remove", params={"id": job_id})
    if after["cleanup"]["response"]["value"] != {"ok": True, "removed": True}:
        raise AdmissionEvidenceError("V2 cron cleanup changed")
    inventory_after_remove = _verify_cron_inventory(
        after["cron_inventory_after_remove"],
        mtime_not_before=after["cleanup"]["command"]["started_at"],
        mtime_not_after=after["system_info_after"]["command"]["started_at"],
    )
    _verify_cron_store_transition(
        inventory_before, inventory_after_add, inventory_after_remove
    )
    sqlite_inodes = {
        snapshot[name]["inode"]
        for snapshot in (inventory_before, inventory_after_add, inventory_after_remove)
        for name in ("database", "shared_memory", "write_ahead_log")
    }
    session_inodes = {
        after["snapshot"]["blob"]["inode"],
        after["snapshot"]["store"]["inode"],
    }
    if sqlite_inodes & session_inodes:
        raise AdmissionEvidenceError("V2 cron state-file inode reused")
    _verify_commands(action, recorded_at)


def _verify_version(command: Mapping[str, Any]) -> None:
    parent.parent.legacy._verify_command(
        command,
        [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ],
        expected_pid=command["pid"],
        stdout_exact=parent.parent.legacy.parent._RUNTIME["version_output"] + "\n",
    )


def _verify_native_call(
    call: Mapping[str, Any], *, method: str, params: Mapping[str, Any]
) -> None:
    if (
        set(call) != {"command", "params", "response"}
        or set(call["response"]) != {"parsed", "value"}
        or call["params"] != params
        or call["response"]["parsed"] is not True
        or type(call["command"]["pid"]) is not int
        or call["command"]["pid"] <= 0
    ):
        raise AdmissionEvidenceError(f"V2 cron {method} call changed")
    parent.parent.legacy._verify_command(
        call["command"],
        parent.parent.legacy._gateway_argv(method, "5000", params),
        expected_pid=call["command"]["pid"],
        stdout_value=call["response"]["value"],
    )


def _verify_system(
    value: Mapping[str, Any], expected_pid: int, expected_hostname: str
) -> None:
    system = value["response"]["value"]
    if (
        set(value) != {"command", "response"}
        or set(value["response"]) != {"parsed", "value"}
        or set(system)
        != {
            "arch",
            "cpuCount",
            "diskAvailableBytes",
            "diskPath",
            "diskTotalBytes",
            "hostname",
            "loadAverage",
            "machineName",
            "memoryFreeBytes",
            "memoryTotalBytes",
            "nodeVersion",
            "osLabel",
            "pid",
            "platform",
            "port",
            "release",
            "uptimeMs",
        }
        or value["response"]["parsed"] is not True
        or system["pid"] != expected_pid
        or type(system["pid"]) is not int
        or system["hostname"] != expected_hostname
        or system["machineName"] != expected_hostname
        or system["diskPath"] != "/var/lib/aragorn-agent-gateway/state"
        or system["arch"] != "arm64"
        or system["platform"] != "linux"
        or system["port"] != 18789
        or type(system["port"]) is not int
        or system["nodeVersion"] != "v24.16.0"
        or system["osLabel"] != "Linux 6.8.0-117-generic"
        or system["release"] != "6.8.0-117-generic"
        or any(
            type(system[field]) is not int
            for field in (
                "cpuCount",
                "diskAvailableBytes",
                "diskTotalBytes",
                "memoryFreeBytes",
                "memoryTotalBytes",
                "uptimeMs",
            )
        )
        or system["cpuCount"] < 0
        or not 0 <= system["diskAvailableBytes"] <= system["diskTotalBytes"]
        or not 0 <= system["memoryFreeBytes"] <= system["memoryTotalBytes"]
        or system["uptimeMs"] <= 0
        or not isinstance(system["loadAverage"], list)
        or len(system["loadAverage"]) != 3
        or any(
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or item < 0
            for item in system["loadAverage"]
        )
    ):
        raise AdmissionEvidenceError("V2 cron system identity changed")
    parent.parent.legacy._verify_command(
        value["command"],
        parent.parent.legacy._gateway_argv("system.info", "5000"),
        expected_pid=value["command"]["pid"],
        stdout_value=system,
    )


def _verify_job(job: Mapping[str, Any]) -> str:
    params = {
        "agentId": "main",
        "delivery": {"mode": "none"},
        "enabled": True,
        "name": cron._CRON_NAME,
        "payload": {
            "kind": "agentTurn",
            "message": "Inert protected cron rescan observation.",
            "model": "openai/gpt-5.5",
            "timeoutSeconds": 5,
        },
        "schedule": {"everyMs": 86_400_000, "kind": "every"},
        "sessionTarget": "isolated",
        "wakeMode": "now",
    }
    _verify_native_call(job, method="cron.add", params=params)
    value = job["response"]["value"]
    job_id = value["id"]
    created = value["createdAtMs"]
    if (
        set(value)
        != {
            "agentId",
            "createdAtMs",
            "delivery",
            "enabled",
            "id",
            "name",
            "nextRunAtMs",
            "payload",
            "schedule",
            "sessionTarget",
            "state",
            "updatedAtMs",
            "wakeMode",
        }
        or cron._UUID4.fullmatch(job_id) is None
        or value["agentId"] != "main"
        or value["enabled"] is not True
        or value["name"] != cron._CRON_NAME
        or value["sessionTarget"] != "isolated"
        or value["wakeMode"] != "now"
        or value["payload"] != params["payload"]
        or value["delivery"] != {"mode": "none"}
        or value["schedule"]
        != {"anchorMs": created, "everyMs": 86_400_000, "kind": "every"}
        or type(created) is not int
        or created <= 0
        or type(value["updatedAtMs"]) is not int
        or type(value["nextRunAtMs"]) is not int
        or value["updatedAtMs"] != created
        or value["nextRunAtMs"] != created + 86_400_000
        or value["state"] != {"nextRunAtMs": value["nextRunAtMs"]}
        or not cron._command_contains_ms(job["command"], created)
    ):
        raise AdmissionEvidenceError("V2 cron job changed")
    return job_id


def _verify_cron_inventory(
    value: Mapping[str, Any],
    *,
    job: Mapping[str, Any] | None = None,
    mtime_not_before: str | None = None,
    mtime_not_after: str,
) -> Mapping[str, Any]:
    params = {"includeDisabled": True, "limit": 200, "offset": 0}
    if set(value) != {"list", "store"}:
        raise AdmissionEvidenceError("V2 cron inventory envelope changed")
    listing = value["list"]
    _verify_native_call(listing, method="cron.list", params=params)
    jobs = [] if job is None else [job]
    previews = (
        {}
        if job is None
        else {job["id"]: {"detail": "not requested", "label": "not requested"}}
    )
    if listing["response"]["value"] != {
        "deliveryPreviews": previews,
        "hasMore": False,
        "jobs": jobs,
        "limit": 200,
        "nextOffset": None,
        "offset": 0,
        "total": len(jobs),
    }:
        raise AdmissionEvidenceError("V2 cron inventory changed")
    if any(
        type(listing["response"]["value"][field]) is not int
        for field in ("limit", "offset", "total")
    ):
        raise AdmissionEvidenceError("V2 cron inventory counters changed")
    store = value["store"]
    if (
        set(store)
        != {"database", "logical_store_path", "shared_memory", "write_ahead_log"}
        or store["logical_store_path"]
        != "/var/lib/aragorn-agent-gateway/state/cron/jobs.json"
    ):
        raise AdmissionEvidenceError("V2 cron store envelope changed")
    for name, suffix in (
        ("database", ""),
        ("shared_memory", "-shm"),
        ("write_ahead_log", "-wal"),
    ):
        identity = store[name]
        if (
            set(identity)
            != {
                "bytes",
                "digest",
                "exists",
                "gid",
                "inode",
                "maximum_bytes",
                "mode",
                "mtime_ns",
                "nlink",
                "path",
                "uid",
            }
            or identity["path"]
            != f"/var/lib/aragorn-agent-gateway/state/state/openclaw.sqlite{suffix}"
            or identity["exists"] is not True
            or identity["uid"] != 992
            or identity["gid"] != 992
            or identity["mode"] != "600"
            or type(identity["nlink"]) is not int
            or identity["nlink"] != 1
            or identity["maximum_bytes"] != 4 * 1024 * 1024
            or type(identity["bytes"]) is not int
            or not 0 < identity["bytes"] <= identity["maximum_bytes"]
            or type(identity["inode"]) is not int
            or identity["inode"] <= 0
            or re.fullmatch(r"[1-9][0-9]*", identity["mtime_ns"]) is None
            or int(identity["mtime_ns"]) // 1_000_000
            > parent.parent.legacy._epoch_ms(mtime_not_after)
            or (
                name != "database"
                and mtime_not_before is not None
                and int(identity["mtime_ns"]) // 1_000_000
                < parent.parent.legacy._epoch_ms(mtime_not_before)
            )
            or re.fullmatch(r"sha256:[0-9a-f]{64}", identity["digest"]) is None
        ):
            raise AdmissionEvidenceError(f"V2 cron SQLite identity changed: {name}")
    return store


def _verify_cron_store_transition(
    before: Mapping[str, Any],
    after_add: Mapping[str, Any],
    after_remove: Mapping[str, Any],
) -> None:
    snapshots = (before, after_add, after_remove)
    stable_fields = (
        "exists",
        "gid",
        "inode",
        "maximum_bytes",
        "mode",
        "nlink",
        "path",
        "uid",
    )
    for name in ("database", "shared_memory", "write_ahead_log"):
        first = snapshots[0][name]
        if any(
            any(item[field] != first[field] for field in stable_fields)
            for item in (snapshot[name] for snapshot in snapshots[1:])
        ):
            raise AdmissionEvidenceError(f"V2 cron SQLite custody changed: {name}")
    if any(
        len(
            {
                snapshot["database"]["inode"],
                snapshot["shared_memory"]["inode"],
                snapshot["write_ahead_log"]["inode"],
            }
        )
        != 3
        for snapshot in snapshots
    ):
        raise AdmissionEvidenceError("V2 cron SQLite inode reused")
    if any(
        len({snapshot[name]["digest"] for name in ("database", "shared_memory", "write_ahead_log")})
        != 3
        for snapshot in snapshots
    ):
        raise AdmissionEvidenceError("V2 cron SQLite digest reused")
    if (
        before["database"] != after_add["database"]
        or before["database"] != after_remove["database"]
        or not (
            int(before["write_ahead_log"]["mtime_ns"])
            < int(after_add["write_ahead_log"]["mtime_ns"])
            < int(after_remove["write_ahead_log"]["mtime_ns"])
        )
        or not (
            before["write_ahead_log"]["bytes"]
            < after_add["write_ahead_log"]["bytes"]
            < after_remove["write_ahead_log"]["bytes"]
        )
        or len({snapshot["write_ahead_log"]["digest"] for snapshot in snapshots}) != 3
        or len({snapshot["shared_memory"]["digest"] for snapshot in snapshots}) != 3
    ):
        raise AdmissionEvidenceError("V2 cron SQLite transition changed")


def _decode_store_raw(value: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    if set(value) != {"base64", "bytes", "digest"}:
        raise AdmissionEvidenceError("V2 cron session-store raw envelope changed")
    raw = base64.b64decode(value["base64"], validate=True)
    if (
        len(raw) > 512 * 1024
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
    ):
        raise AdmissionEvidenceError("V2 cron session-store raw identity changed")
    document = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=parent.parent.legacy.parent._reject_duplicates,
        parse_constant=parent.parent.legacy.parent._reject_constant,
    )
    if type(document) is not dict:
        raise AdmissionEvidenceError("V2 cron session-store document changed")
    _verify_route_scalar_types(document)
    return raw, document


def _verify_pre_run(
    value: Mapping[str, Any], store_before: Mapping[str, Any], job_id: str
) -> Mapping[str, Any]:
    store = value["store"]
    raw, document = _decode_store_raw(value["store_raw"])
    base_session_key = f"agent:main:cron:{job_id}"
    if (
        set(value)
        != {
            "base_entry_present",
            "base_session_key",
            "completed_at",
            "started_at",
            "store",
            "store_document_digest",
            "store_raw",
            "top_level_keys",
        }
        or set(store)
        != {
            "bytes",
            "digest",
            "gid",
            "inode",
            "mode",
            "mtime_ns",
            "nlink",
            "path",
            "uid",
        }
        or value["base_entry_present"] is not False
        or value["base_session_key"] != base_session_key
        or base_session_key in document
        or value["store_document_digest"] != _digest(raw)
        or value["store_document_digest"] != store_before["digest"]
        or value["top_level_keys"] != ["agent:main:aragorn-worker-coherent"]
        or value["top_level_keys"] != sorted(document)
        or store["path"] != _SESSION_STORE
        or store_before["path"] != _SESSION_STORE
        or store["digest"] != store_before["digest"]
        or store["digest"] != _digest(raw)
        or store["bytes"] != store_before["size"]
        or store["bytes"] != len(raw)
        or store["inode"] != store_before["inode"]
        or store["uid"] != 992
        or store["gid"] != 992
        or store["mode"] != "600"
        or type(store["nlink"]) is not int
        or store["nlink"] != 1
        or not isinstance(store["mtime_ns"], str)
        or re.fullmatch(r"[1-9][0-9]*", store["mtime_ns"]) is None
        or int(store["mtime_ns"]) // 1_000_000
        > parent.parent.legacy._epoch_ms(value["completed_at"])
        or parent.parent.legacy._parse_time(value["started_at"])
        > parent.parent.legacy._parse_time(value["completed_at"])
    ):
        raise AdmissionEvidenceError("V2 cron pre-run state changed")
    return document


def _verify_snapshot(
    value: Mapping[str, Any],
    job_id: str,
    pre_store_document: Mapping[str, Any],
) -> None:
    blob = value["blob"]
    entry = value["entry"]
    entry_document = value["entry_document"]
    snapshot = value["snapshot"]
    metadata = snapshot["metadata"]
    store = value["store"]
    raw, store_document = _decode_store_raw(value["store_raw"])
    base_session_key = f"agent:main:cron:{job_id}"
    prompt_ref = {
        "algorithm": "sha256",
        "bytes": len(parent._PROMPT),
        "hash": parent._PROMPT_DIGEST.removeprefix("sha256:"),
        "version": 1,
    }
    expected_store_document = dict(pre_store_document)
    expected_store_document[base_session_key] = entry_document
    canonical_entry = parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
        entry_document
    )
    canonical_store = parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
        store_document
    )
    if (
        set(value)
        != {
            "base_session_key",
            "blob",
            "entry",
            "entry_digest",
            "entry_document",
            "prompt",
            "snapshot",
            "store",
            "store_document",
            "store_document_bytes",
            "store_document_digest",
            "store_raw",
            "store_top_level_keys",
        }
        or set(entry)
        != {
            "label",
            "lifecycle_revision",
            "model",
            "model_provider",
            "session_id_present",
            "session_key",
            "system_sent",
            "updated_at",
        }
        or set(entry_document)
        != {
            "label",
            "lifecycleRevision",
            "model",
            "modelProvider",
            "skillsSnapshot",
            "systemSent",
            "updatedAt",
        }
        or set(entry_document["skillsSnapshot"])
        != {
            "promptFormatVersion",
            "promptRef",
            "skillFilter",
            "skills",
            "version",
        }
        or set(snapshot) != {"metadata", "metadata_digest", "prompt_ref_present"}
        or set(blob)
        != {
            "bytes",
            "digest",
            "gid",
            "inode",
            "mode",
            "mtime_ns",
            "nlink",
            "path",
            "prompt_ref",
            "uid",
        }
        or set(store)
        != {
            "bytes",
            "digest",
            "gid",
            "inode",
            "mode",
            "mtime_ns",
            "nlink",
            "path",
            "uid",
        }
        or value["base_session_key"] != base_session_key
        or entry
        != {
            "label": entry_document["label"],
            "lifecycle_revision": entry_document["lifecycleRevision"],
            "model": entry_document["model"],
            "model_provider": entry_document["modelProvider"],
            "session_id_present": False,
            "session_key": base_session_key,
            "system_sent": entry_document["systemSent"],
            "updated_at": entry_document["updatedAt"],
        }
        or entry_document["label"] != f"Cron: {cron._CRON_NAME}"
        or cron._UUID4.fullmatch(entry_document["lifecycleRevision"]) is None
        or entry_document["model"] != "gpt-5.5"
        or entry_document["modelProvider"] != "openai"
        or entry_document["systemSent"] is not True
        or type(entry_document["updatedAt"]) is not int
        or entry_document["updatedAt"] <= 0
        or value["entry_digest"] != _digest(canonical_entry)
        or value["prompt"]
        != {
            "bytes": len(parent._PROMPT),
            "digest": parent._PROMPT_DIGEST,
            "exact_text": parent._PROMPT.decode(),
            "inline_prompt_present": False,
            "storage": "promptRef",
        }
        or snapshot["prompt_ref_present"] is not True
        or metadata
        != {
            "promptFormatVersion": 1,
            "skillFilter": ["template-skill"],
            "skills": [{"name": "template-skill"}],
            "version": metadata["version"],
        }
        or type(metadata["version"]) is not int
        or metadata["version"] <= 0
        or metadata["version"] > entry_document["updatedAt"]
        or type(metadata["promptFormatVersion"]) is not int
        or type(entry_document["skillsSnapshot"]["promptRef"]["version"])
        is not int
        or snapshot["metadata_digest"] != _canonical_digest(metadata)
        or entry_document["skillsSnapshot"] != {**metadata, "promptRef": prompt_ref}
        or blob["bytes"] != len(parent._PROMPT)
        or blob["digest"] != parent._PROMPT_DIGEST
        or blob["prompt_ref"] != prompt_ref
        or blob["path"] != parent._PROMPT_PATH
        or blob["uid"] != 992
        or blob["gid"] != 992
        or blob["mode"] != "600"
        or type(blob["nlink"]) is not int
        or blob["nlink"] != 1
        or type(blob["prompt_ref"]["version"]) is not int
        or type(blob["inode"]) is not int
        or blob["inode"] <= 0
        or blob["inode"] == store["inode"]
        or re.fullmatch(r"[1-9][0-9]*", blob["mtime_ns"]) is None
        or store["path"] != _SESSION_STORE
        or store["uid"] != 992
        or store["gid"] != 992
        or store["mode"] != "600"
        or type(store["nlink"]) is not int
        or store["nlink"] != 1
        or type(store["inode"]) is not int
        or store["inode"] <= 0
        or re.fullmatch(r"[1-9][0-9]*", store["mtime_ns"]) is None
        or store["bytes"] != len(raw)
        or store["digest"] != _digest(raw)
        or store["bytes"] > 512 * 1024
        or parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
            value["store_document"]
        )
        != canonical_store
        or value["store_document"] != expected_store_document
        or store_document.get(base_session_key) != entry_document
        or value["store_document_bytes"] != len(canonical_store)
        or value["store_document_bytes"] > 512 * 1024
        or value["store_document_digest"] != _digest(canonical_store)
        or value["store_top_level_keys"] != sorted(store_document)
        or value["store_top_level_keys"]
        != sorted([*pre_store_document, base_session_key])
    ):
        raise AdmissionEvidenceError("V2 cron snapshot changed")


def _verify_terminal(
    result: Mapping[str, Any],
    *,
    job: Mapping[str, Any],
    request: Mapping[str, Any],
    poll: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    job_id: str,
    run_id: str,
) -> None:
    match = cron._RUN_ID.fullmatch(run_id)
    run_epoch = int(match.group(2)) if match is not None else -1
    diagnostic = result["diagnostics"]["entries"][0]
    session_id = result["sessionId"]
    if (
        set(result)
        != {
            "action",
            "deliveryStatus",
            "diagnostics",
            "durationMs",
            "error",
            "errorReason",
            "jobId",
            "jobName",
            "model",
            "nextRunAtMs",
            "provider",
            "runAtMs",
            "runId",
            "sessionId",
            "sessionKey",
            "status",
            "ts",
        }
        or set(result["diagnostics"]) != {"entries", "summary"}
        or set(diagnostic) != {"message", "severity", "source", "ts"}
        or match is None
        or match.group(1) != job_id
        or result["action"] != "finished"
        or result["status"] != "error"
        or result["errorReason"] != "model_not_found"
        or result["error"] != "FailoverError: Unknown model: openai/gpt-5.5"
        or result["provider"] != "openai"
        or result["model"] != "gpt-5.5"
        or result["jobId"] != job_id
        or result["jobName"] != cron._CRON_NAME
        or result["runId"] != run_id
        or cron._UUID4.fullmatch(session_id) is None
        or result["sessionKey"] != f"agent:main:cron:{job_id}:run:{session_id}"
        or result["deliveryStatus"] != "not-requested"
        or result["diagnostics"]["summary"] != "Unknown model: openai/gpt-5.5"
        or len(result["diagnostics"]["entries"]) != 1
        or diagnostic
        != {
            "message": "Unknown model: openai/gpt-5.5",
            "severity": "error",
            "source": "agent-run",
            "ts": diagnostic["ts"],
        }
        or result["nextRunAtMs"] != job["response"]["value"]["nextRunAtMs"]
        or type(result["durationMs"]) is not int
        or result["durationMs"] < 0
        or result["durationMs"] > result["ts"] - result["runAtMs"]
        or any(
            type(value) is not int or value <= 0
            for value in (
                result["nextRunAtMs"],
                result["runAtMs"],
                result["ts"],
                diagnostic["ts"],
            )
        )
        or not parent.parent.legacy._epoch_ms(request["command"]["started_at"])
        <= run_epoch
        <= result["runAtMs"]
        <= parent.parent.legacy._epoch_ms(request["command"]["completed_at"])
        <= snapshot["entry"]["updated_at"]
        <= int(snapshot["store"]["mtime_ns"]) // 1_000_000
        <= int(snapshot["blob"]["mtime_ns"]) // 1_000_000
        <= diagnostic["ts"]
        <= result["ts"]
        <= parent.parent.legacy._epoch_ms(poll["command"]["completed_at"])
    ):
        raise AdmissionEvidenceError("V2 cron terminal causality changed")
    if result["runAtMs"] != run_epoch:
        raise AdmissionEvidenceError("V2 cron run identity changed")


def _verify_store(
    value: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    before: Mapping[str, Any],
) -> None:
    if (
        set(value)
        != {
            "device",
            "digest",
            "digest_error",
            "exists",
            "gid",
            "inode",
            "mode",
            "nlink",
            "path",
            "size",
            "type",
            "uid",
        }
        or value["path"] != _SESSION_STORE
        or value["exists"] is not True
        or value["type"] != "file"
        or value["uid"] != 992
        or value["gid"] != 992
        or value["mode"] != "600"
        or type(value["nlink"]) is not int
        or value["nlink"] != 1
        or type(value["device"]) is not int
        or value["device"] <= 0
        or value["device"] != before["device"]
        or value["size"] != snapshot["bytes"]
        or value["digest"] != snapshot["digest"]
        or value["inode"] != snapshot["inode"]
        or value["inode"] != before["inode"]
        or value["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("V2 cron retained session store changed")


def _verify_commands(action: Mapping[str, Any], recorded_at: str) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    commands = action["commands"]
    expected = [
        before["version"],
        before["system_info_before"]["command"],
        before["cron_inventory_before"]["list"]["command"],
        after["job"]["command"],
        after["cron_inventory_after_add"]["list"]["command"],
        after["run"]["request"]["command"],
        after["run"]["terminal_poll"]["command"],
        after["cleanup"]["command"],
        after["cron_inventory_after_remove"]["list"]["command"],
        after["system_info_after"]["command"],
    ]
    pre_run = after["session_state_before_forced_run"]
    if (
        commands != expected
        or len(commands) != 10
        or any(
            type(command["pid"]) is not int or command["pid"] <= 0
            for command in commands
        )
        or len({command["pid"] for command in commands}) != 10
        or any(
            parent.parent.legacy._parse_time(left["completed_at"])
            > parent.parent.legacy._parse_time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or parent.parent.legacy._parse_time(
            after["cron_inventory_after_add"]["list"]["command"]["completed_at"]
        )
        > parent.parent.legacy._parse_time(pre_run["started_at"])
        or parent.parent.legacy._parse_time(pre_run["completed_at"])
        > parent.parent.legacy._parse_time(
            after["run"]["request"]["command"]["started_at"]
        )
        or parent.parent.legacy._parse_time(commands[-1]["completed_at"])
        > parent.parent.legacy._parse_time(recorded_at)
    ):
        raise AdmissionEvidenceError("V2 cron command causality changed")
