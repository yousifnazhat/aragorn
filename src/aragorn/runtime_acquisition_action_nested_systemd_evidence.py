"""Verify the bounded P3.8d depth-one acquisition-to-action observation."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import runtime_acquisition_action_multifile_systemd_evidence as p38c
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest, canonical_json

p38b = p38c.p38b

_SCHEMA = "aragorn/runtime-acquisition-action-nested-systemd-observation/v1"
_AUTHORITY = (
    "BOUNDED_LIVE_COORDINATOR_DEPTH_ONE_TWO_FILE_ACQUISITION_TO_RUNTIME_ACTION_"
    "OBSERVATION_ONLY_NOT_VERIFIED_RUN_EDR_INSTALLER_RELEASE_AUTHORITY"
)
_RETAINED_PATH = (
    "benchmark/evidence/runtime-acquisition-action-nested-systemd-composition-"
    "p3-8d-2026-08-11.json"
)
_EVIDENCE_BYTES = 546_229
_EVIDENCE_RAW_DIGEST = (
    "sha256:da54ca66ed01ac86c1996bace65260b1a02c2e80887e0bba76559520c6614329"
)
_EVIDENCE_DIGEST = (
    "sha256:d47e9486c4890cf69a9c58d2fd8a0a51bfa34eeabfe4d0c58112fce26a9654e0"
)
_RECORDED_AT = "2026-08-11T11:36:09.516868Z"
_SOURCE_COMMIT = "58e4b69fe6607812a306fb04d386f2bc7a41adde"
_PARENT_IMAGE = p38c._CHILD_IMAGE
_CHILD_IMAGE = "sha256:fb4794e886c2bef6ab450d28fc59ee3347ed2c2426d116c81781dc1d4bf09847"
_TREE_DIGEST = "sha256:4e7924cb5ede0268e04dd4089a571c463e2d92ff8500239f6177fb2e393cd0e1"
_TOP_LEVEL = p38c._TOP_LEVEL
_P38C_RECEIPT_PATH = (
    "benchmark/receipts/phase3-runtime-acquisition-action-multifile-systemd-"
    "qualification-v1-2026-08-11.json"
)
_P38C_RECEIPT_BYTES = 5_071
_P38C_RECEIPT_RAW_DIGEST = (
    "sha256:b55dac129c9163f0ea5391ba39bdf0e2534a63bd6834932bfd372b1ef03f6a1d"
)
_P38C_RECEIPT_DIGEST = (
    "sha256:81e1305f0210c76c6acb5647ed9df6e4f15e39adcd4670f105c9eec08d89d6c2"
)
_P38C_VERIFIER_DIGEST = (
    "sha256:4b4bf4255b9a4290cb3d4c93861086ad4fac5b34b8c59e91afe30ecfd9ecbe4c"
)
_SECTION_DIGESTS = {
    "acquisition": "sha256:30e6a3cb61ba115d1010a2d16bf4350f56e515534f75a9c58190981721c86bf7",
    "action": "sha256:d0546019d6a45d82929e287381569b55b0e24af2d59832f8b50d39481ba604d0",
    "artifacts": "sha256:a58ff81157860cc041621b05bec65babee56c789cd7d5e63b1299030b7dc2e34",
    "bindings": "sha256:f63a61af8b4005fa9b4c32d500f45d5c1f076866b5366bca3a79e9b54a8e4890",
    "harness": "sha256:df63770863dc2ba753275d3cec78cf2756f85c853d849f6cbb351e838d2c3916",
}
_ACQUISITION_ENVELOPE_DIGEST = _SECTION_DIGESTS["acquisition"]
_ACTION_ENVELOPE_DIGEST = _SECTION_DIGESTS["action"]
_HARNESS_DIGEST = (
    "sha256:8c7c6fc8a853404f23c29cddea683898ce0efd1a6301d13c7c3b7e75166dbf61"
)
_IMAGE_LINEAGE_DIGEST = (
    "sha256:78c849e7ea781e6efe70c65f6d8420696827bc16b7d3d38eb316c4f838190365"
)
_ACTION_CASE_DIGESTS = {
    "coherent_consumed": "sha256:fd1863c99efbe9a6fa144832a9fa6fb542dfc989083f2dda46994f8e0552b790",
    "expired_fail_stop": "sha256:be01642b44f50da08466cce188dc612d9df163c1e30f9ede263914b4e33b3dbd",
    "full_activation": "sha256:47d43f43bc06d8a2e3838b99875b01352d38d838abe3a9f12dd6e635d6b7afb8",
    "terminal_archive_rotation": "sha256:ea298379c0dad2f5c9457aeae4dfed2d0ca8e2f8f7ea0f3c883b5aea2223dc9f",
}
_COLLECTOR_DIGEST = (
    "sha256:e53d147054b40643f119cdc065a89b631dc18c2f91959db10c26ea8fb3cdfa39"
)
_P38C_COLLECTOR_DIGEST = p38c._COLLECTOR_DIGEST
_P38C_OVERLAY_DIGEST = (
    "sha256:ac0d1b3319d76a4ddf0ed3f579c544991a9c218fbd04faaa2f19edabf1e262c0"
)
_P38C_OVERLAY_CLOSURE_DIGEST = (
    "sha256:99da687a7053dfed18d1b23fa65a8dd4febfec5bfb9af265da8e70db2fa2ced3"
)
_P38D_OVERLAY_DIGEST = (
    "sha256:6494fc81d38021c7e33c44c9cf198e8d7cc25bfbad22b6de8d85063caa7e1d16"
)
_P38D_OVERLAY_CLOSURE_DIGEST = (
    "sha256:3b2f668895471b034f3aec54a060310a4d5044a2aa178558c0d9072b0234b1fb"
)
_ACTION_ARTIFACTS_PROJECTION_DIGEST = (
    "sha256:e4231516e8758982f5e82057483b0fd5bd82bd7808a78879220a731b4838fc98"
)
_GATEWAY_CONFIG_DIGEST = (
    "sha256:980ec5e431058e2a35f842d190c292ae906abf4b1032fa21b25f123c2200ff2e"
)
_TRANSACTION_DIGEST = (
    "sha256:0665b796dba1f27a59175bd08a9766d5c0170a4c16ed1fbcd9dc7ad11c00b232"
)
_SERVICE_RECEIPT_DIGEST = (
    "sha256:635b4441577111ab0497c65f2d3485e7e75a6a4a388d0b562e4e8f9b7f13e715"
)
_SERVICE_REQUEST_DIGEST = (
    "sha256:41dc43579535846c3dfd90e970d529505a8c138be14ac47b8a91cc1fd39a2a08"
)
_COORDINATOR_RESULT_DIGEST = (
    "sha256:cc53ad07d286b170b0153937f86c8d69f6d917c9d5ec4d147a293e31959f084a"
)
_COORDINATOR_STATE_DIGEST = (
    "sha256:d41fa3e8bfa5b086efee9cbe6e69c751d458c2da355584dc327a88cc264adcfc"
)
_QUARANTINE_RECEIPT_DIGEST = (
    "sha256:75804e6408f40333cc590e83ceaa64fc5cf5a508a05b8565b8c67781e0fc6dab"
)
_SOURCE_REQUEST = {
    "commit": "9b081280bc52ee6f22a2e0463761b318936dd980",
    "owner": "affaan-m",
    "repository": "ecc",
    "schema": "aragorn/github-gateway-request/v1",
    "skill_path": "skills/brand-voice",
}
_QUARANTINE_NAMESPACE = (
    "/var/lib/aragorn-quarantine/"
    "32ba298962af0b1845812b2ee4ee053bdf4dff51d610683a3a468efb055e811d"
)
_TREE_ENTRIES = [
    {
        "digest": "sha256:57c7f8440b7bd4c91c0d325640b5c6fb7a3dc7fc05595946c7bc705761a987a7",
        "executable": False,
        "path": "SKILL.md",
        "size": 3_648,
    },
    {
        "digest": "sha256:3c5c2b04fd4b68642d2d3279829541bc56d211fdefc3498e86c1486abee8261b",
        "executable": False,
        "path": "references/voice-profile-schema.md",
        "size": 1_063,
    },
]
_DIRECTORIES = ("references",)
_LIMITATIONS = [
    "ADAPTED_PYTHON_3_12_CURRENT_RELEASE_NOT_RETAINED_PHASE1_RELEASE_IDENTITY",
    (
        "ONE_EXACT_THIRD_PARTY_PUBLIC_TWO_FILE_DEPTH_ONE_MARKDOWN_SOURCE_ONLY_"
        "NOT_GENERAL_NESTED_COVERAGE"
    ),
    "ONE_NONEMPTY_DIRECT_DIRECTORY_ONLY_DEEPER_RECURSION_NOT_QUALIFIED",
    "ONE_EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_ACTION_ONLY",
    "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "SYSTEMD_252_CGROUP_AND_DOCKER_DNS_ADAPTERS_ARE_FIXTURE_ONLY",
    "NETWORK_DISCONNECTION_IS_WRAPPER_CONTROLLED_AND_PROBE_REVERIFIED",
    (
        "TWO_SOURCE_FILES_AND_ONE_DIRECTORY_ARE_BOUND_TO_THE_ACTION_WITHOUT_"
        "SEMANTIC_CAUSATION_AUTHORITY"
    ),
    "P3_7C_RUNTIME_FLOW_IS_REUSED_WITHOUT_PROMOTING_ITS_PARENT_QUALIFICATION",
    "NO_AGGREGATE_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
]
_DECISION = {
    "bounded_depth_one_two_file_tree_observed": True,
    "bounded_two_file_tree_observed": True,
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
    "status": "P3_8D_OBSERVED_NOT_VERIFIED",
}
_QUALIFICATION_LIMITATIONS = [
    *_LIMITATIONS[:-1],
    (
        "QUARANTINE_CAS_METADATA_AND_DEPTH_ONE_TWO_FILE_BYTES_RETAINED_NOT_FULL_"
        "NON_SKILL_BLOB_REPLAY"
    ),
    "PROVIDER_AND_OPENCLAW_SESSION_RAW_BYTES_NOT_RETAINED",
    "TRACE_PROVES_ONE_ROUTE_CONNECT_WITHOUT_RETRY_NOT_APPLICATION_SEND_COUNT",
    (
        "ACTIVE_RECORD_AND_CLAIM_CUSTODY_TIMESTAMPS_NOT_RETAINED_DEVICE_INODE_"
        "MODE_SIZE_ONLY"
    ),
    "PROTECTED_SERVICE_REQUEST_BYTES_NOT_RETAINED_DIGEST_JOIN_ONLY",
    "PYTHON_STDLIB_AND_DYNAMIC_VERIFIER_DEPENDENCY_CLOSURE_NOT_PINNED",
    _LIMITATIONS[-1],
]
_QUALIFICATION_DECISION = {
    "aggregate_gate_eligible": False,
    "bounded_depth_one_two_file_tree_verified": True,
    "bounded_live_acquisition_action_evidence_eligible": True,
    "bounded_two_file_tree_verified": True,
    "edr_claim_eligible": False,
    "installer_authority_eligible": False,
    "live_same_custody_install_to_action_verified": True,
    "network_disconnected_before_runtime_verified": True,
    "one_coherent_allow_created_consumed_action_verified": True,
    "parent_p3_8c_unchanged": True,
    "phase3_exit_eligible": False,
    "public_release_eligible": False,
    "qualified_pair_retained_evidence_eligible": True,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "same_phase1_release_identity": False,
    "semantic_skill_causation_established": False,
    "source_observation_unchanged": True,
    "source_observation_verified": True,
    "status": "P3_8D_BOUNDED_DEPTH_ONE_TWO_FILE_PASS",
}


def verify_runtime_acquisition_action_nested_systemd_evidence(
    document: Mapping[str, Any],
    p38c_observation: Mapping[str, Any],
    p38b_observation: Mapping[str, Any],
    p37c_observation: Mapping[str, Any],
    p37b_observation: Mapping[str, Any],
    p36b_observation: Mapping[str, Any],
    p37b_receipt: Mapping[str, Any],
    p37c_receipt: Mapping[str, Any],
    p38b_receipt: Mapping[str, Any],
    p38c_receipt: Mapping[str, Any],
    *,
    expected_digest: str | None,
) -> None:
    """Replay the exact P3.8d observation without promoting broader authority."""

    try:
        _expect(expected_digest == _EVIDENCE_DIGEST, "retained digest pin changed")
        _expect(
            not p38b.p37c.parent_verifier._contains_float(document), "float is invalid"
        )
        values = tuple(
            _snapshot(value)
            for value in (
                document,
                p38c_observation,
                p38b_observation,
                p37c_observation,
                p37b_observation,
                p36b_observation,
                p37b_receipt,
                p37c_receipt,
                p38b_receipt,
                p38c_receipt,
            )
        )
        document = values[0]
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
        _expect(
            canonical_json(document["limitations"]) == canonical_json(_LIMITATIONS),
            "source ceiling changed",
        )
        _expect(
            canonical_json(document["decision"]) == canonical_json(_DECISION),
            "source decision changed",
        )
        _verify_parent(*values[1:])
        _verify_observation(document, values[3])
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        IndexError,
        KeyError,
        StopIteration,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid runtime acquisition action nested systemd evidence: {exc}"
        ) from exc


def runtime_acquisition_action_nested_systemd_qualification(
    document: Mapping[str, Any],
    p38c_observation: Mapping[str, Any],
    p38b_observation: Mapping[str, Any],
    p37c_observation: Mapping[str, Any],
    p37b_observation: Mapping[str, Any],
    p36b_observation: Mapping[str, Any],
    p37b_receipt: Mapping[str, Any],
    p37c_receipt: Mapping[str, Any],
    p38b_receipt: Mapping[str, Any],
    p38c_receipt: Mapping[str, Any],
    *,
    expected_digest: str | None,
    implementation_digest: str | None = None,
) -> dict[str, Any]:
    """Return the deterministic bounded P3.8d qualification."""

    try:
        values = tuple(
            _snapshot(value)
            for value in (
                document,
                p38c_observation,
                p38b_observation,
                p37c_observation,
                p37b_observation,
                p36b_observation,
                p37b_receipt,
                p37c_receipt,
                p38b_receipt,
                p38c_receipt,
            )
        )
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid runtime acquisition action nested systemd evidence: {exc}"
        ) from exc
    verify_runtime_acquisition_action_nested_systemd_evidence(
        *values, expected_digest=expected_digest
    )
    verifier_digest = _raw_digest(Path(__file__).read_bytes())
    _expect(
        implementation_digest is not None and implementation_digest == verifier_digest,
        "verifier implementation pin changed",
    )
    document = values[0]
    acquisition = document["acquisition"]
    transaction = acquisition["protected"]["transaction"]
    coherent = document["action"]["cases"]["coherent_consumed"]
    return {
        "assurance": (
            "SEMANTICALLY_REPLAY_VERIFIED_PINNED_LIVE_DEPTH_ONE_TWO_FILE_"
            "ACQUISITION_TO_ONE_COHERENT_RUNTIME_ACTION"
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
                    "bytes": p38c._EVIDENCE_BYTES,
                    "canonical_digest": p38c._EVIDENCE_DIGEST,
                    "path": p38c._RETAINED_PATH,
                    "raw_digest": p38c._EVIDENCE_RAW_DIGEST,
                },
                "receipt": {
                    "bytes": _P38C_RECEIPT_BYTES,
                    "canonical_digest": _P38C_RECEIPT_DIGEST,
                    "path": _P38C_RECEIPT_PATH,
                    "raw_digest": _P38C_RECEIPT_RAW_DIGEST,
                },
            },
            "implementation": {
                "p38c_verifier_digest": _P38C_VERIFIER_DIGEST,
                "verifier_implementation_digest": verifier_digest,
            },
            "acquisition": {
                "context_id": transaction["context_id"],
                "manifest_digest": transaction["manifest_digest"],
                "source_request": dict(acquisition["source_request"]),
                "tree_digest": transaction["tree_digest"],
            },
            "depth_one_two_file_tree": {
                "directories": list(_DIRECTORIES),
                "entries": list(_TREE_ENTRIES),
                "projected_tree_digest": document["bindings"]["projected_tree"][
                    "after_action"
                ]["tree_digest"],
                "protected_tree_digest": document["bindings"]["protected_tree"][
                    "after_action"
                ]["tree_digest"],
            },
            "runtime_action": {
                "consumed_state_digest": coherent["grant_state"]["digest"],
                "fresh_grant_digest": document["action"]["inputs"]["fresh_grant"][
                    "digest"
                ],
                "target_digest": coherent["target"]["digest"],
            },
        },
        "cases": {
            "live_depth_one_two_file_acquisition": {
                "directory_count": 1,
                "file_count": acquisition["quarantine"]["receipt"]["file_count"],
                "status": "PASS",
                "tree_digest": transaction["tree_digest"],
            },
            "nested_directory_custody": {
                "directories": list(_DIRECTORIES),
                "mode": "0555",
                "owner": "0:0",
                "status": "PASS",
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
        "schema": "aragorn/runtime-acquisition-action-nested-systemd-qualification/v1",
        "source_recorded_at": document["recorded_at"],
    }


def _verify_parent(*args: Mapping[str, Any]) -> None:
    expected = p38c.runtime_acquisition_action_multifile_systemd_qualification(
        *args[:-1],
        expected_digest=p38c._EVIDENCE_DIGEST,
        implementation_digest=_P38C_VERIFIER_DIGEST,
    )
    p38b._require_receipt(
        args[-1],
        expected,
        digest=_P38C_RECEIPT_DIGEST,
        raw_digest=_P38C_RECEIPT_RAW_DIGEST,
        size=_P38C_RECEIPT_BYTES,
    )


def _verify_observation(
    document: Mapping[str, Any], p37c_observation: Mapping[str, Any]
) -> None:
    _expect(
        all(
            canonical_digest(document[name]) == digest
            for name, digest in _SECTION_DIGESTS.items()
        ),
        "pinned section changed",
    )
    _expect(
        canonical_digest(document["acquisition"]) == _ACQUISITION_ENVELOPE_DIGEST
        and canonical_digest(document["action"]) == _ACTION_ENVELOPE_DIGEST,
        "fixed retained envelope changed",
    )
    _verify_record_closure(document)
    _verify_artifacts(document["artifacts"])
    _verify_harness(document["harness"])
    acquisition = _verify_acquisition(document["acquisition"])
    action = _verify_action(
        document["action"], document["harness"], p37c_observation, acquisition
    )
    _verify_bindings(document["bindings"], acquisition, action)
    _verify_network(document, acquisition)
    _verify_custody_windows(document)


def _verify_record_closure(document: Mapping[str, Any]) -> None:
    records = {
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
            "files": 206,
            "raw": 136,
            "commands": 53,
            "sockets": 31,
            "clocks": 8,
        },
        "retained record closure changed",
    )
    for value in records["documents"]:
        _expect(
            value["digest"] == canonical_digest(value["document"]),
            "document changed",
        )
    for value in records["files"]:
        (
            p38b._verify_bounded_file
            if "path" in value["stat"]
            else p38b.p37c._verify_file
        )(value)
    for value in records["raw"]:
        p38b.p37c._verify_raw(value)
    for value in records["commands"]:
        p38b.p37c._verify_command(value)
    for value in records["sockets"]:
        p38b.p37c._verify_socket_record(value, value["path"])
    for value in records["clocks"]:
        p38b.p37c._verify_clock(value)


def _verify_artifacts(value: Mapping[str, Any]) -> None:
    _expect(
        set(value)
        == {
            "collector",
            "gateway_adaptation",
            "installed",
            "p3_8c_collector",
            "p3_8c_overlay",
            "p3_8d_overlay",
            "parent_collector",
            "release_identity",
        },
        "artifact fields changed",
    )
    p38b._verify_artifacts(
        {
            "collector": value["parent_collector"],
            "gateway_adaptation": value["gateway_adaptation"],
            "installed": value["installed"],
            "release_identity": value["release_identity"],
        }
    )
    _verify_collector(
        value["p3_8c_collector"],
        _P38C_COLLECTOR_DIGEST,
        {
            "capture_recipe": (
                "/src/scripts/capture_runtime_acquisition_action_multifile_systemd.sh"
            ),
            "dockerfile": (
                "/src/benchmark/runtime-acquisition-action-multifile-systemd/Dockerfile"
            ),
            "probe": (
                "/src/scripts/runtime_acquisition_action_multifile_systemd_probe.py"
            ),
        },
    )
    _verify_collector(
        value["collector"],
        _COLLECTOR_DIGEST,
        {
            "capture_recipe": (
                "/src/scripts/capture_runtime_acquisition_action_nested_systemd.sh"
            ),
            "dockerfile": (
                "/src/benchmark/runtime-acquisition-action-nested-systemd/Dockerfile"
            ),
            "probe": (
                "/src/scripts/runtime_acquisition_action_nested_systemd_probe.py"
            ),
        },
    )
    _verify_overlay(
        value["p3_8c_overlay"],
        expected_digest=_P38C_OVERLAY_DIGEST,
        expected_closure_digest=_P38C_OVERLAY_CLOSURE_DIGEST,
        expected={
            "acquire.py": (
                "sha256:56942e7c1b10c58f265615c8b7abf3f199c7f98bf016be50eb6d3a98d2bd0f8c",
                "/src/src/aragorn/acquire.py",
                "/usr/lib/aragorn/aragorn/acquire.py",
                "0444",
                "0644",
            ),
            "cas.py": (
                "sha256:c5642f910ac4b2d6172a59a02105b359cb43d3a2f2e2240368229d3436ad4859",
                "/src/src/aragorn/cas.py",
                "/usr/lib/aragorn/aragorn/cas.py",
                "0444",
                "0644",
            ),
            "runtime_active_skill_lineage.py": (
                "sha256:7f5fc7aa979efd0a719904d14b2d8576b80af302572882de90dca464291db726",
                (
                    "/opt/aragorn-p38c-overwritten-artifacts/source/"
                    "runtime_active_skill_lineage.py"
                ),
                (
                    "/opt/aragorn-p38c-overwritten-artifacts/installed/"
                    "runtime_active_skill_lineage.py"
                ),
                "0444",
                "0644",
            ),
            "runtime_process_profile.py": (
                "sha256:a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68",
                "/src/src/aragorn/runtime_process_profile.py",
                "/usr/lib/aragorn/aragorn/runtime_process_profile.py",
                "0444",
                "0644",
            ),
            "activate-runtime-action-worker-host.sh": (
                "sha256:466261b94b832da010a2f27896335731cfcaeb3a87d8c15767b80c6aceb752bb",
                (
                    "/opt/aragorn-p38c-overwritten-artifacts/source/"
                    "activate-runtime-action-worker-host.sh"
                ),
                (
                    "/opt/aragorn-p38c-overwritten-artifacts/installed/"
                    "activate-runtime-action-worker-host.sh"
                ),
                "0555",
                "0755",
            ),
        },
    )
    _verify_overlay(
        value["p3_8d_overlay"],
        expected_digest=_P38D_OVERLAY_DIGEST,
        expected_closure_digest=_P38D_OVERLAY_CLOSURE_DIGEST,
        expected={
            "runtime_active_skill_lineage.py": (
                "sha256:6d1663d097410838d6c9b69644ffdfb2bd7ace30091d31544f31b04a7f6776d1",
                "/src/src/aragorn/runtime_active_skill_lineage.py",
                "/usr/lib/aragorn/aragorn/runtime_active_skill_lineage.py",
                "0444",
                "0644",
            ),
            "activate-runtime-action-worker-host.sh": (
                "sha256:b395941f2ebfbb5593460e125cbcb4d9a1aea9a6ec63a09baa181dfd350a5ab2",
                "/src/packaging/activate-runtime-action-worker-host.sh",
                "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh",
                "0555",
                "0755",
            ),
        },
    )


def _verify_collector(
    value: Mapping[str, Any], digest: str, paths: Mapping[str, str]
) -> None:
    _expect(
        set(value) == set(paths) == {"capture_recipe", "dockerfile", "probe"}
        and canonical_digest(value) == digest,
        "collector closure changed",
    )
    for name, record in value.items():
        p38b.p37c._verify_file(record)
        _expect(
            record["path"] == paths[name]
            and record["stat"]["uid"] == record["stat"]["gid"] == 0
            and record["stat"]["mode"] == ("0444" if name == "dockerfile" else "0555")
            and record["stat"]["nlink"] == 1,
            "collector custody changed",
        )


def _verify_overlay(
    value: Mapping[str, Any],
    *,
    expected_digest: str,
    expected_closure_digest: str,
    expected: Mapping[str, tuple[str, str, str, str, str]],
) -> None:
    _expect(
        set(value)
        == {
            "build_inputs",
            "installed",
            "installed_closure",
            "installed_closure_digest",
        }
        and canonical_digest(value) == expected_digest
        and [pair["name"] for pair in value["installed"]] == list(expected),
        "overlay shape changed",
    )
    closure = []
    identities = set()
    for pair in value["installed"]:
        _expect(set(pair) == {"installed", "name", "source"}, "overlay pair changed")
        digest, source_path, installed_path, source_mode, installed_mode = expected[
            pair["name"]
        ]
        source = pair["source"]
        installed = pair["installed"]
        p38b.p37c._verify_file(source)
        p38b.p37c._verify_file(installed)
        _expect(
            source["digest"] == installed["digest"] == digest
            and source["bytes"] == installed["bytes"]
            and source["path"] == source_path
            and installed["path"] == installed_path
            and source["stat"]["uid"] == source["stat"]["gid"] == 0
            and installed["stat"]["uid"] == installed["stat"]["gid"] == 0
            and source["stat"]["mode"] == source_mode
            and installed["stat"]["mode"] == installed_mode
            and source["stat"]["nlink"] == installed["stat"]["nlink"] == 1,
            "overlay source/install join changed",
        )
        identities.update(
            {
                (source["stat"]["device"], source["stat"]["inode"]),
                (installed["stat"]["device"], installed["stat"]["inode"]),
            }
        )
        closure.append(
            {
                "bytes": installed["bytes"],
                "digest": installed["digest"],
                "mode": installed["stat"]["mode"],
                "name": pair["name"],
                "path": installed["path"],
            }
        )
    _expect(
        len(identities) == 2 * len(expected)
        and canonical_json(closure) == canonical_json(value["installed_closure"])
        and canonical_digest(closure)
        == value["installed_closure_digest"]
        == expected_closure_digest,
        "overlay closure or custody changed",
    )
    build_inputs = value["build_inputs"]
    expected_inputs = {
        "install-runtime-action-worker-host.sh": (
            "/src/packaging/install-runtime-action-worker-host.sh",
            "sha256:885441b628298629cc07d5c68e52b852864c6a755bc10d0e7e5de406f17b4748",
        ),
        "install-runtime-capability-host.sh": (
            "/src/packaging/install-runtime-capability-host.sh",
            "sha256:6a7b4ec084b4dee8d974a0acab183f850be57e0acff30b616040687b307d28d9",
        ),
    }
    _expect(set(build_inputs) == set(expected_inputs), "overlay build inputs changed")
    for name, record in build_inputs.items():
        p38b.p37c._verify_file(record)
        path, digest = expected_inputs[name]
        _expect(
            record["path"] == path
            and record["digest"] == digest
            and record["stat"]["uid"] == record["stat"]["gid"] == 0
            and record["stat"]["mode"] == "0555"
            and record["stat"]["nlink"] == 1,
            "overlay build input changed",
        )


def _verify_harness(value: Mapping[str, Any]) -> Mapping[str, Any]:
    _expect(
        set(value) == {"container_cgroup", "digest", "document", "file"},
        "harness fields changed",
    )
    harness = p38b.p37c._verify_document_snapshot(
        {key: value[key] for key in ("digest", "document", "file")}
    )
    cgroup = p38b._verify_bounded_file(value["container_cgroup"])
    lineage = harness["image_lineage"]
    _expect(
        value["digest"] == _HARNESS_DIGEST
        and harness["schema"]
        == "aragorn/runtime-acquisition-action-nested-systemd-harness/v1"
        and harness["capture_disposition"]
        == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and harness["platform"] == "linux"
        and harness["profile_label"] == "p3.8d"
        and harness["source_commit"] == _SOURCE_COMMIT
        and harness["parent_image_id"] == lineage["parent"]["id"] == _PARENT_IMAGE
        and harness["image_id"]
        == harness["run_image_reference"]
        == lineage["child"]["id"]
        == _CHILD_IMAGE
        and canonical_digest(lineage) == _IMAGE_LINEAGE_DIGEST
        and lineage["child"]["layers"]
        == [*lineage["parent"]["layers"], *lineage["added_layers"]]
        and len(lineage["added_layers"]) == 6
        and cgroup == f"0::/docker/{harness['container_id']}/init.scope\n".encode()
        and harness["host_config"]["privileged"] is True
        and harness["host_config"]["readonly_rootfs"] is False
        and harness["published_ports"] == {}
        and value["file"]["path"] == "/run/aragorn-harness.json"
        and value["file"]["stat"]["uid"] == value["file"]["stat"]["gid"] == 0
        and value["file"]["stat"]["mode"] == "0600"
        and value["file"]["stat"]["nlink"] == 1,
        "harness lineage or custody changed",
    )
    verification = harness["source_commit_verification"]
    commit = p38b.p37c._verify_raw(verification["commit_object"])
    _expect(
        verification["command"] == ["git", "verify-commit", "--raw", _SOURCE_COMMIT]
        and verification["exit_code"] == 0
        and hashlib.sha1(f"commit {len(commit)}\0".encode() + commit).hexdigest()
        == _SOURCE_COMMIT
        and b"gpgsig " in commit,
        "source commit verification changed",
    )
    return harness


def _verify_tree(value: Mapping[str, Any], root_path: str) -> dict[str, Any]:
    _expect(
        set(value) == {"directories", "entries", "files", "root", "tree_digest"}
        and canonical_json(value["entries"]) == canonical_json(_TREE_ENTRIES)
        and value["tree_digest"] == canonical_digest(value["entries"]) == _TREE_DIGEST
        and set(value["files"]) == {entry["path"] for entry in _TREE_ENTRIES}
        and set(value["directories"]) == set(_DIRECTORIES),
        "depth-one two-file tree shape changed",
    )
    root = value["root"]
    p38b._verify_path_record(root)
    _expect(
        root["path"] == root_path
        and root["type"] == "directory"
        and root["uid"] == root["gid"] == 0
        and root["mode"] == "0555"
        and root["nlink"] == 3,
        "depth-one tree root changed",
    )
    directory = value["directories"][_DIRECTORIES[0]]
    p38b._verify_path_record(directory)
    _expect(
        directory["path"] == f"{root_path}/{_DIRECTORIES[0]}"
        and directory["type"] == "directory"
        and directory["uid"] == directory["gid"] == 0
        and directory["mode"] == "0555"
        and directory["nlink"] == 2
        and directory["device"] == root["device"],
        "depth-one directory custody changed",
    )
    raw = {}
    identities = {
        (root["device"], root["inode"]),
        (directory["device"], directory["inode"]),
    }
    for entry in _TREE_ENTRIES:
        record = value["files"][entry["path"]]
        raw[entry["path"]] = p38b._verify_bounded_file(record)
        _expect(
            record["path"] == f"{root_path}/{entry['path']}"
            and record["bytes"] == entry["size"]
            and record["digest"] == entry["digest"]
            and record["stat"]["uid"] == record["stat"]["gid"] == 0
            and record["stat"]["mode"] == "0444"
            and record["stat"]["nlink"] == 1
            and record["stat"]["device"] == root["device"],
            "depth-one tree entry changed",
        )
        identities.add((record["stat"]["device"], record["stat"]["inode"]))
    _expect(len(identities) == 4, "depth-one tree custody identity changed")
    return {"identities": identities, "raw": raw}


def _verify_cas(value: Mapping[str, Any], namespace: str) -> set[tuple[int, int]]:
    closure = {
        "sha256:0728087bcc02b8329bef3f8c49f54048d1d9ec621bfa746ea3c4852edfe4459d": 51,
        "sha256:3c5c2b04fd4b68642d2d3279829541bc56d211fdefc3498e86c1486abee8261b": 1_063,
        "sha256:3e8a0022933dba62f1d5736600206b98aea2c3f0db150464d3b18bc54d0be14c": 956,
        "sha256:432e826ee5f2c64cdfdb8a771ca6a539a25c3ae224b19eb7ab722367e31841af": 1_055,
        "sha256:53684d7055b1e2a19acb5e48d5557afa6e7f76a872b2c247bb7c6d90ac8615d7": 73,
        "sha256:57c7f8440b7bd4c91c0d325640b5c6fb7a3dc7fc05595946c7bc705761a987a7": 3_648,
        "sha256:653758d43334a4233838e5068e37406f051f2a0530282cd22ae0eb84ddcad8dc": 3_183,
        "sha256:75804e6408f40333cc590e83ceaa64fc5cf5a508a05b8565b8c67781e0fc6dab": 1_482,
        "sha256:8663d13f07ca0f527cce01e74af76b594e5d44585bb1f03b57501213c6e32032": 4_238,
        "sha256:8c0bccda729329737eb445567f043230b2fa744e90e5a503e6cf079eb751650e": 1_299,
        "sha256:b0ec57e6626cb4d072c18865ad412ca8732f0c7c3ee0babcfaa2c6695cd78627": 12_659,
    }
    _expect(
        set(value) == {"blobs", "closure", "closure_digest", "root"}
        and canonical_json(value["closure"]) == canonical_json(closure)
        and value["closure_digest"]
        == canonical_digest(
            [
                {"bytes": size, "digest": digest}
                for digest, size in sorted(closure.items())
            ]
        ),
        "CAS closure changed",
    )
    root = value["root"]
    p38b._verify_path_record(root)
    _expect(
        root["path"] == namespace
        and root["type"] == "directory"
        and root["uid"] == root["gid"] == 0
        and root["mode"] == "0700"
        and root["nlink"] == 3,
        "CAS root changed",
    )
    observed = {}
    identities = set()
    for item in value["blobs"]:
        file = item["file"]
        p38b._verify_path_record(file)
        _expect(
            set(item) == {"bytes", "digest", "file"}
            and item["bytes"] == closure[item["digest"]] == file["size"]
            and file["path"]
            == f"{namespace}/blobs/sha256/{item['digest'][7:9]}/{item['digest'][9:]}"
            and file["type"] == "file"
            and file["uid"] == file["gid"] == 0
            and file["mode"] == "0444"
            and file["nlink"] == 1
            and file["device"] == root["device"],
            "CAS blob changed",
        )
        observed[item["digest"]] = item["bytes"]
        identities.add((file["device"], file["inode"]))
    _expect(
        observed == closure
        and len(value["blobs"]) == len(identities) == 11
        and (root["device"], root["inode"]) not in identities,
        "CAS inventory changed",
    )
    return identities | {(root["device"], root["inode"])}


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
        and canonical_json(value["source_request"]) == canonical_json(_SOURCE_REQUEST),
        "acquisition fields changed",
    )
    coordinator = value["coordinator"]
    result = coordinator["result"]
    command = coordinator["command"]
    path_start = coordinator["path_unit_start"]
    stdout = p38b.p37c._verify_raw(command["stdout"])
    state = p38b.p37c._verify_document_snapshot(coordinator["state"])
    active = state["expected_active"]
    _expect(
        set(coordinator) == {"command", "path_unit_start", "result", "state"}
        and set(result)
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
        and set(state)
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
        and command["argv"]
        == [
            "/usr/local/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/aragorn-protected-install-coordinator.py",
            "submit",
            "install",
            _SOURCE_REQUEST["owner"],
            _SOURCE_REQUEST["repository"],
            _SOURCE_REQUEST["commit"],
            _SOURCE_REQUEST["skill_path"],
        ]
        and command["exit_code"] == 0
        and json.loads(stdout) == result
        and stdout == canonical_json(result) + b"\n"
        and canonical_digest(result) == _COORDINATOR_RESULT_DIGEST
        and canonical_digest(state) == _COORDINATOR_STATE_DIGEST
        and result["schema"] == "aragorn/protected-install-coordinator-result/v1"
        and result["operation"] == "install"
        and result["status"] == "COMPLETED_NOT_INSTALLER_AUTHORITY"
        and result["assurance"]
        == "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
        and result["quarantine_authority"] == "QUARANTINE_ONLY_NOT_ADMISSION_AUTHORITY"
        and result["service_request_digest"] == _SERVICE_REQUEST_DIGEST
        and result["installer_work_eligible"] is False
        and result["runtime_conformance_qualified"] is False
        and state["schema"] == "aragorn/protected-install-coordinator-state/v3"
        and state["assurance"] == result["assurance"]
        and state["service_request_digest"] == result["service_request_digest"]
        and path_start["argv"]
        == ["systemctl", "start", "aragorn-protected-install-coordinator.path"]
        and path_start["exit_code"] == 0
        and path_start["signal"] is None
        and p38b.p37c._verify_raw(path_start["stdout"]) == b""
        and p38b.p37c._verify_raw(path_start["stderr"]) == b""
        and coordinator["state"]["file"]["path"]
        == "/var/lib/aragorn-protected/coordinator-active.json"
        and coordinator["state"]["file"]["stat"]["uid"]
        == coordinator["state"]["file"]["stat"]["gid"]
        == 0
        and coordinator["state"]["file"]["stat"]["mode"] == "0400"
        and coordinator["state"]["file"]["stat"]["nlink"] == 1
        and result["source_request"] == _SOURCE_REQUEST
        and active["source_request"] == _SOURCE_REQUEST
        and all(
            active[field] == result[field]
            for field in (
                "context_id",
                "gateway_profile_digest",
                "manifest_digest",
                "quarantine_receipt_digest",
            )
        )
        and state["tree_digest"] == _TREE_DIGEST,
        "coordinator state/result join changed",
    )
    quarantine = value["quarantine"]
    receipt = quarantine["receipt"]
    request_digest = canonical_digest(_SOURCE_REQUEST)
    _expect(
        set(quarantine)
        == {
            "cas_after_runtime",
            "cas_before_runtime",
            "namespace",
            "receipt",
            "receipt_digest",
            "source_files",
            "source_skill",
        }
        and set(receipt)
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
        and quarantine["namespace"] == _QUARANTINE_NAMESPACE
        and quarantine["namespace"]
        == f"/var/lib/aragorn-quarantine/{request_digest[7:]}"
        and receipt["schema"] == "aragorn/github-quarantine-receipt/v1"
        and receipt["authority"] == "QUARANTINE_ONLY_NOT_ADMISSION_AUTHORITY"
        and receipt["request"] == _SOURCE_REQUEST
        and receipt["request_digest"] == request_digest
        and receipt["source_assurance"]
        == "git_smart_http_v2_commit_tree_proof_and_api_blob_identity_reverified"
        and receipt["containment_profile"] == "linux-systemd-restricted-egress/v1"
        and isinstance(receipt["file_count"], int)
        and not isinstance(receipt["file_count"], bool)
        and receipt["file_count"] == 2
        and receipt["tree_digest"] == _TREE_DIGEST
        and receipt["tree_digest"] == state["tree_digest"]
        and receipt["manifest_digest"]
        == active["recursive"]["root_manifest_digest"]
        == "sha256:3e8a0022933dba62f1d5736600206b98aea2c3f0db150464d3b18bc54d0be14c"
        and receipt["handoff_manifest_digest"]
        == "sha256:432e826ee5f2c64cdfdb8a771ca6a539a25c3ae224b19eb7ab722367e31841af"
        and receipt["source_closure_digest"]
        == "sha256:988dad809a877ed752cdf80134cbebef484ef5f89b3274c2d675966edf0133fc"
        and receipt["source_proof_digest"]
        == "sha256:8c0bccda729329737eb445567f043230b2fa744e90e5a503e6cf079eb751650e"
        and receipt["gateway_profile_digest"]
        == result["gateway_profile_digest"]
        == "sha256:297201c776e8c510f4ca62a8c5e41d3a9d0b73125d84c963088b5a7836df5686"
        and receipt["gateway"]
        == {
            "package_tree_digest": (
                "sha256:b877b340ed6efc8f1cb61e3404d0afaf86a0e49a5410a2ce4151bc6a57b07fa5"
            ),
            "python_executable_digest": p38b.p36b._PYTHON_DIGEST,
        }
        and isinstance(receipt["receipt_id"], str)
        and len(receipt["receipt_id"]) == 64
        and all(character in "0123456789abcdef" for character in receipt["receipt_id"])
        and canonical_digest(receipt) == _QUARANTINE_RECEIPT_DIGEST
        and quarantine["receipt_digest"]
        == canonical_digest(receipt)
        == result["quarantine_receipt_digest"],
        "quarantine receipt changed",
    )
    cas_identities = _verify_cas(
        quarantine["cas_before_runtime"], quarantine["namespace"]
    )
    cas_root = quarantine["cas_before_runtime"]["root"]
    protected_cas = receipt["protected_cas"]
    _expect(
        cas_identities
        == _verify_cas(quarantine["cas_after_runtime"], quarantine["namespace"])
        and quarantine["cas_before_runtime"] == quarantine["cas_after_runtime"],
        "CAS changed through runtime",
    )
    _expect(
        set(protected_cas) == {"mode", "owner_uid", "root_device", "root_inode"}
        and all(
            isinstance(protected_cas[field], int)
            and not isinstance(protected_cas[field], bool)
            for field in ("mode", "owner_uid", "root_device", "root_inode")
        )
        and protected_cas
        == {
            "mode": int(cas_root["mode"], 8),
            "owner_uid": cas_root["uid"],
            "root_device": cas_root["device"],
            "root_inode": cas_root["inode"],
        },
        "quarantine receipt CAS custody changed",
    )
    source_files = {
        name: p38b.p37c._verify_raw(record)
        for name, record in quarantine["source_files"].items()
    }
    _expect(
        set(source_files) == {entry["path"] for entry in _TREE_ENTRIES}
        and p38b.p37c._verify_raw(quarantine["source_skill"])
        == source_files["SKILL.md"]
        and all(
            quarantine["source_files"][entry["path"]]["digest"] == entry["digest"]
            and len(source_files[entry["path"]]) == entry["size"]
            for entry in _TREE_ENTRIES
        ),
        "quarantine source files changed",
    )
    protected = value["protected"]
    transaction = protected["transaction"]
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
            "tree",
            "tree_entries",
            "tree_entry",
            "version",
        }
        and transaction["schema"] == "aragorn/protected-install-transaction/v1"
        and transaction["context_id"] == result["context_id"]
        and transaction["manifest_digest"] == result["manifest_digest"]
        and transaction["tree_digest"] == _TREE_DIGEST
        and transaction["version_path"] == state["version_path"]
        and canonical_digest(transaction) == _TRANSACTION_DIGEST
        and canonical_json(protected["tree_entries"]) == canonical_json(_TREE_ENTRIES)
        and protected["tree_entry"] == _TREE_ENTRIES[0],
        "protected transaction changed",
    )
    _verify_artifact_graph_closure(
        protected["service_receipt"], result, active, receipt, transaction
    )
    version_path = f"/var/lib/aragorn-protected/skills/{transaction['version_path']}"
    tree = _verify_tree(protected["tree"], version_path)
    _expect(
        tree["raw"] == source_files
        and protected["skill"] == protected["tree"]["files"]["SKILL.md"],
        "source/install bytes changed",
    )
    record = protected["record"]
    claim = protected["claim"]
    link = protected["active_link"]
    version = protected["version"]
    root_device = transaction["destination"]["root_device"]
    p38b._verify_path_record(link)
    p38b._verify_path_record(version)
    _expect(
        set(record) == {"digest", "document", "file", "raw_digest"}
        and canonical_json(record["document"])
        == canonical_json(
            {
                "authority": (
                    "BROKER_ACTIVE_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
                ),
                "schema": "aragorn/protected-active-runtime/v1",
                "transaction": transaction,
            }
        )
        and record["digest"]
        == record["raw_digest"]
        == record["file"]["digest"]
        == canonical_digest(record["document"])
        and record["file"]["bytes"] == len(canonical_json(record["document"]))
        and record["file"]["stat"]["size"] == record["file"]["bytes"]
        and set(claim) == {"digest", "document", "file", "raw_digest"}
        and canonical_json(claim["document"]) == canonical_json(transaction)
        and claim["digest"]
        == claim["raw_digest"]
        == claim["file"]["digest"]
        == canonical_digest(transaction)
        and claim["file"]["bytes"] == len(canonical_json(transaction))
        and claim["file"]["stat"]["size"] == claim["file"]["bytes"]
        and canonical_digest(protected["service_receipt"]) == _SERVICE_RECEIPT_DIGEST
        and protected["service_receipt"]["transaction"] == transaction
        and protected["service_receipt"]["source"]["request"] == _SOURCE_REQUEST
        and record["file"]["path"]
        == "/var/lib/aragorn-protected/skills/.aragorn-active-runtime.json"
        and record["file"]["stat"]["uid"] == record["file"]["stat"]["gid"] == 0
        and record["file"]["stat"]["device"] == root_device
        and record["file"]["stat"]["mode"] == "0444"
        and record["file"]["stat"]["nlink"] == 1
        and claim["file"]["path"]
        == (
            "/var/lib/aragorn-protected/skills/.aragorn-install-claims/"
            f"{transaction['context_id'][7:]}.json"
        )
        and claim["file"]["stat"]["uid"] == claim["file"]["stat"]["gid"] == 0
        and claim["file"]["stat"]["device"] == root_device
        and claim["file"]["stat"]["mode"] == "0400"
        and claim["file"]["stat"]["nlink"] == 1
        and link["type"] == "symlink"
        and link["path"] == "/var/lib/aragorn-protected/skills/aragorn-admitted"
        and link["target"] == transaction["version_path"]
        and link["device"] == root_device
        and link["uid"] == link["gid"] == 0
        and link["mode"] == "0777"
        and link["nlink"] == 1
        and link["size"] == len(link["target"].encode())
        and version == protected["tree"]["root"]
        and version["path"] == version_path
        and version["device"] == protected["tree"]["root"]["device"] == root_device
        and version["type"] == "directory"
        and version["uid"] == version["gid"] == 0
        and version["mode"] == "0555"
        and version["nlink"] == 3,
        "protected custody join changed",
    )
    protected_identities = {
        (record["file"]["stat"]["device"], record["file"]["stat"]["inode"]),
        (claim["file"]["stat"]["device"], claim["file"]["stat"]["inode"]),
        (link["device"], link["inode"]),
        *tree["identities"],
    }
    _expect(
        len(protected_identities) == 7
        and protected_identities.isdisjoint(cas_identities),
        "protected custody identity changed",
    )
    p38b._verify_service_journal(
        protected["service_journal_identity"],
        value["journals"]["aragorn-protected-install.service"],
        protected["service_receipt"],
        value["timing"],
    )
    journals = value["journals"]
    journal_since = f"@{p38b._time(value['timing']['started_at']).timestamp():.6f}"
    journal_until = f"@{p38b._time(value['timing']['completed_at']).timestamp():.6f}"
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
            and item["command"]["argv"]
            == [
                "journalctl",
                "--all",
                "--no-pager",
                "--output=json",
                "--unit",
                unit,
                "--since",
                journal_since,
                "--until",
                journal_until,
            ]
            and item["command"]["exit_code"] == 0
            and len(
                [
                    json.loads(line)
                    for line in p38b.p37c._verify_raw(
                        item["command"]["stdout"]
                    ).splitlines()
                ]
            )
            == item["entry_count"]
            for unit, item in journals.items()
        ),
        "acquisition journal inventory changed",
    )
    return {
        "network": value["network"],
        "record": record,
        "cas_identities": cas_identities,
        "protected_identities": protected_identities,
        "service_journal_boot_id": protected["service_journal_identity"]["boot_id"],
        "skill": protected["skill"],
        "source_files": source_files,
        "timing": value["timing"],
        "transaction": transaction,
        "tree": protected["tree"],
    }


def _verify_artifact_graph_closure(
    service_receipt: Mapping[str, Any],
    coordinator_result: Mapping[str, Any],
    coordinator_active: Mapping[str, Any],
    quarantine_receipt: Mapping[str, Any],
    transaction: Mapping[str, Any],
) -> None:
    source = service_receipt["source"]
    analyzer = service_receipt["analyzer"]
    decision = service_receipt["decision"]
    recursive = source["recursive"]
    _expect(
        set(service_receipt)
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
        and service_receipt["schema"]
        == "aragorn/openclaw-github-protected-install-broker-evidence/v1"
        and service_receipt["assurance"]
        == (
            "LIVE_GITHUB_CUSTODY_TO_PROTECTED_INSTALL_EVIDENCE_ONLY_NOT_"
            "INSTALLER_AUTHORITY"
        )
        and service_receipt["mode"] == "github-live"
        and service_receipt["slice_status"] == "PASS"
        and service_receipt["producer_implementation_digest"]
        == p38b.p36b._BROKER_DIGEST
        and service_receipt["limitations"] == p38b.p36b._RECEIPT_LIMITATIONS
        and service_receipt["transition"]
        == {"expected_active": None, "manifest_diff": None, "operation": "install"}
        and service_receipt["transaction"] == transaction
        and service_receipt["verified_sequence"]
        == [
            "quarantine-custody",
            "recursive-github-markdown/v1-closure",
            "exact-source-materialization",
            "digest-bound-first-party-analyzer-run",
            "decision-v3-replay",
            "protected-install-context-v2",
            "protected-install-transaction",
            "active-tree-reverification",
        ]
        and set(source)
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
        and set(decision)
        == {"digest", "installer_work_eligible", "policy_digest", "verdict"}
        and canonical_json(decision)
        == canonical_json(
            {
                "digest": (
                    "sha256:a61384c472abf1d47b829352595bc94b1b6fac8978249ada0f10d34992c08a89"
                ),
                "installer_work_eligible": False,
                "policy_digest": (
                    "sha256:aa90f135d9634ce22428ffd17a780044b11ae13755b7c16ea427ae8aa684232f"
                ),
                "verdict": "ALLOW",
            }
        )
        and set(recursive)
        == {
            "expansion_digest",
            "expansion_proof_digest",
            "release_asset_result_digests",
            "release_pin_set_digest",
            "root_manifest_digest",
        }
        and recursive
        == {
            "expansion_digest": (
                "sha256:1c648cc6ebe4c2919e5d76a9c6b8269edb5dbaba45380588889914baf7f80603"
            ),
            "expansion_proof_digest": (
                "sha256:10d676709152c41286e9f256227c718d586237c378fa6cf0289b7361366f39f8"
            ),
            "release_asset_result_digests": [],
            "release_pin_set_digest": (
                "sha256:9092411c41524544a8a0eddcb78ae888f374ea58cfcb0a10467bcc340c7715ae"
            ),
            "root_manifest_digest": (
                "sha256:3e8a0022933dba62f1d5736600206b98aea2c3f0db150464d3b18bc54d0be14c"
            ),
        }
        and analyzer
        == {
            "configuration_digest": (
                "sha256:21e168d5992a9a5c43b087b68810e661807f1b0db03bd9b9b6c729e054aebe1a"
            ),
            "executable_digest": (
                "sha256:7863a4d5e03fde7791c7f8c2c304cf3522f435e19745364ad18a6b7a0458af57"
            ),
            "execution_identity": {
                "gid": 993,
                "group": "aragorn-analyze",
                "supplementary_groups": [],
                "uid": 993,
                "user": "aragorn-analyze",
            },
            "implementation_digest": (
                "sha256:190f4aad373350e17db38de05433cba685864a4a8fc4ef09d1dca77f12fe6350"
            ),
            "name": "aragorn-agent-skill-threats",
            "run_receipt_digest": (
                "sha256:31c96fb39495a22b1210ff5c8de52f0b205ade4289d6f5d5963cde334ac968b7"
            ),
            "verifier_implementation_digest": (
                "sha256:6d4a54c3206e9ab5cc767131f35de7587f7f6d05707a69d9f52028fda5821e45"
            ),
            "version": "0.1.0-phase0-v7",
        }
        and source["artifact_count"] == quarantine_receipt["file_count"] == 2
        and source["artifact_graph_digest"]
        == "sha256:c1b9963c6f63ea65e8adbb02909f1ffbf769b34699d0b9ab232b8101c8cd8171"
        and source["artifact_graph_profile"] == "recursive-github-markdown/v1"
        and source["artifact_graph_verifier_implementation_digest"]
        == analyzer["implementation_digest"]
        and source["closure"]
        == {
            "profile": "recursive-github-markdown/v1",
            "scope": "artifact_graph",
            "status": "complete",
            "unresolved": [],
        }
        and source["request"] == quarantine_receipt["request"] == _SOURCE_REQUEST
        and recursive == coordinator_active["recursive"]
        and recursive["root_manifest_digest"] == quarantine_receipt["manifest_digest"]
        and source["manifest_digest"]
        == transaction["manifest_digest"]
        == coordinator_result["manifest_digest"]
        and source["tree_digest"]
        == transaction["tree_digest"]
        == quarantine_receipt["tree_digest"]
        == _TREE_DIGEST
        and source["source_closure_digest"]
        == quarantine_receipt["source_closure_digest"]
        and source["source_proof_digest"] == quarantine_receipt["source_proof_digest"]
        and source["quarantine_receipt_digest"]
        == canonical_digest(quarantine_receipt)
        == coordinator_result["quarantine_receipt_digest"]
        and source["gateway_profile_digest"]
        == quarantine_receipt["gateway_profile_digest"]
        == coordinator_result["gateway_profile_digest"]
        and source["gateway"] == quarantine_receipt["gateway"]
        and source["containment_profile"] == quarantine_receipt["containment_profile"]
        and source["quarantine_protected_cas"] == quarantine_receipt["protected_cas"]
        and service_receipt["active"]
        == {
            "link_target": transaction["version_path"],
            "tree_digest": transaction["tree_digest"],
        },
        "recursive artifact graph or analyzer closure changed",
    )
    _verify_request_credential(service_receipt["request_authority"], coordinator_result)
    context = service_receipt["context"]
    claim = service_receipt["claim"]
    snapshot = claim["initial_revocation_snapshot"]
    fresh = claim["fresh"]
    claim_now = fresh["claim_now_unix"]
    credential = service_receipt["request_authority"]["credential"]
    _expect(
        canonical_json(context)
        == canonical_json(
            {
                "context_id": transaction["context_id"],
                "destination": transaction["destination"],
                "digest": transaction["context_digest"],
                "expected_active": None,
                "operation": "install",
                "runtime_conformance_digest": p38b._RUNTIME_CONFORMANCE_DIGEST,
                "target_runtime_digest": p38b.p36b._RUNTIME_DIGEST,
            }
        ),
        "service receipt context changed",
    )
    _expect(
        set(claim) == {"fresh", "initial_revocation_snapshot"}
        and set(fresh) == {"claim_now_unix", "revocation_snapshot"}
        and canonical_json(fresh["revocation_snapshot"]) == canonical_json(snapshot)
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
        and snapshot["digest"] == p38b._REVOCATION_DIGEST
        and snapshot["device"] == transaction["destination"]["root_device"]
        and snapshot["device"] > 0
        and snapshot["inode"] > 0
        and isinstance(claim_now, int)
        and not isinstance(claim_now, bool)
        and credential["ctime_ns"] // 1_000_000_000
        <= claim_now
        <= credential["ctime_ns"] // 1_000_000_000 + 5,
        "service receipt claim changed",
    )


def _verify_request_credential(
    authority: Mapping[str, Any], coordinator_result: Mapping[str, Any]
) -> None:
    credential = authority["credential"]
    _expect(
        set(authority)
        == {"authority", "credential", "request_digest", "request_schema"}
        and authority["authority"] == "PROTECTED_CANONICAL_REQUEST_CREDENTIAL"
        and authority["request_digest"] == coordinator_result["service_request_digest"]
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
        and credential["size"] == 2_156
        and credential["device"] > 0
        and credential["inode"] > 0
        and credential["mtime_ns"] == credential["ctime_ns"] > 0,
        "service request credential changed",
    )


def _verify_action(
    value: Mapping[str, Any],
    harness: Mapping[str, Any],
    p37c_observation: Mapping[str, Any],
    acquisition: Mapping[str, Any],
) -> dict[str, Any]:
    _expect(
        set(value) == p38b.p37c._TOP_LEVEL
        and value["authority"] == p38b.p37c._AUTHORITY
        and canonical_json(value["decision"]) == canonical_json(p38b.p37c._DECISION)
        and canonical_json(value["limitations"])
        == canonical_json(p38b.p37c._LIMITATIONS)
        and value["identities"] == p37c_observation["identities"]
        and value["runtime"] == p37c_observation["runtime"]
        and value["parent"] == p37c_observation["parent"]
        and value["harness"] == harness
        and set(value["artifacts"]) == set(p37c_observation["artifacts"])
        and value["artifacts"]["installed_closure_digest"]
        == "sha256:2d8178f5e2692acbdfd65b85f9bec2ab8245e43ed9313ebdbf690f6cf07cb963"
        and canonical_digest(p38b._artifact_projection(value["artifacts"]))
        == _ACTION_ARTIFACTS_PROJECTION_DIGEST,
        "nested action identity changed",
    )
    artifact_records = []

    def collect_artifacts(child: Any) -> None:
        if isinstance(child, Mapping):
            if {"bytes", "digest", "path", "stat"}.issubset(child):
                artifact_records.append(child)
            for nested in child.values():
                collect_artifacts(nested)
        elif isinstance(child, list):
            for nested in child:
                collect_artifacts(nested)

    collect_artifacts(value["artifacts"])
    _expect(
        len(artifact_records)
        == len({record["path"] for record in artifact_records})
        == len(
            {
                (record["stat"]["device"], record["stat"]["inode"])
                for record in artifact_records
            }
        )
        == 93,
        "nested action artifact custody identity changed",
    )
    _expect(
        set(value["cases"]) == set(_ACTION_CASE_DIGESTS)
        and all(
            case["status"] == "OBSERVED"
            and all(result is True for result in case["checks"].values())
            and canonical_digest(case) == _ACTION_CASE_DIGESTS[name]
            for name, case in value["cases"].items()
        ),
        "nested action cases changed",
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
        "gateway environment retention claim changed",
    )
    producer = inputs["producer"]
    _expect(
        set(producer)
        == {
            "directories",
            "projected_skill",
            "projected_tree",
            "protected_tree",
            "record",
            "skill",
            "transaction",
            "tree_entries",
        }
        and producer["directories"] == list(_DIRECTORIES)
        and producer["transaction"] == acquisition["transaction"]
        and producer["record"] == acquisition["record"]
        and canonical_json(producer["tree_entries"]) == canonical_json(_TREE_ENTRIES)
        and producer["skill"]["digest"] == _TREE_ENTRIES[0]["digest"]
        and producer["projected_skill"]["digest"] == producer["skill"]["digest"]
        and all(
            producer["skill"][field] == acquisition["skill"][field]
            for field in ("bytes", "digest", "path")
        )
        and producer["skill"]["stat"]
        == {key: acquisition["skill"]["stat"][key] for key in producer["skill"]["stat"]}
        and all(
            producer["projected_skill"][field]
            == producer["projected_tree"]["files"]["SKILL.md"][field]
            for field in ("bytes", "digest", "path")
        )
        and producer["projected_skill"]["stat"]
        == {
            key: producer["projected_tree"]["files"]["SKILL.md"]["stat"][key]
            for key in producer["projected_skill"]["stat"]
        },
        "action producer changed",
    )
    protected = _verify_tree(
        producer["protected_tree"], acquisition["tree"]["root"]["path"]
    )
    projected_root = "/var/lib/aragorn-agent-gateway/state/skills/brand-voice"
    projected = _verify_tree(producer["projected_tree"], projected_root)
    _expect(
        protected["raw"] == projected["raw"] == acquisition["source_files"]
        and producer["projected_skill"]["path"] == f"{projected_root}/SKILL.md"
        and projected["identities"].isdisjoint(acquisition["protected_identities"])
        and projected["identities"].isdisjoint(acquisition["cas_identities"]),
        "action depth-one projection changed",
    )
    action = inputs["action"]
    policy = inputs["policy"]
    _expect(
        inputs["policy_digest"] == canonical_digest(policy)
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
    p38b.action_decision._policy(policy)
    _expect(
        canonical_digest(inputs["gateway_config"]) == _GATEWAY_CONFIG_DIGEST,
        "gateway configuration changed",
    )
    container_id = harness["document"]["container_id"]
    p38b.p37c._verify_profiles(value["profiles"], producer, container_id)
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
        grant = p38b.parse_runtime_capability_grant(canonical_json(wrapper["document"]))
        _expect(
            canonical_json(wrapper["document"]) == canonical_json(grant)
            and wrapper["digest"] == canonical_digest(grant)
            and grant["active_skill_digest"] == producer["skill"]["digest"]
            and grant["source_manifest_digest"]
            == producer["transaction"]["manifest_digest"]
            and grant["install_context_digest"]
            == producer["transaction"]["context_digest"],
            f"{name} binding changed",
        )
        grants[name] = {"digest": wrapper["digest"], "document": grant}
    short_source = inputs["short_grant"]["source"]
    grant_source = inputs["grant_source"]
    _expect(
        p38b.p37c._verify_document_snapshot(short_source)
        == grants["short_grant"]["document"]
        and p38b.p37c._verify_document_snapshot(grant_source)
        == grants["fresh_grant"]["document"]
        and all(
            source["file"]["path"] == "/etc/aragorn/runtime-capability-grant.json"
            and source["file"]["stat"]["type"] == "file"
            and source["file"]["stat"]["uid"] == source["file"]["stat"]["gid"] == 0
            and source["file"]["stat"]["mode"] == "0400"
            and source["file"]["stat"]["nlink"] == 1
            for source in (short_source, grant_source)
        ),
        "grant source custody changed",
    )
    binding = inputs["worker_binding"]
    binding_file = inputs["worker_binding_file"]
    _expect(
        binding
        == {
            "active_skill_digest": producer["skill"]["digest"],
            "policy_digest": inputs["policy_digest"],
            "policy_version": policy["version"],
            "runtime_digest": value["runtime"]["tree"]["tree_digest"],
            "schema": "aragorn/runtime-action-worker-binding/v1",
        }
        and binding_file["path"] == "/etc/aragorn/runtime-action-worker.json"
        and binding_file["digest"] == canonical_digest(binding)
        and binding_file["bytes"] == len(canonical_json(binding))
        and binding_file["stat"]["type"] == "file"
        and binding_file["stat"]["uid"] == binding_file["stat"]["gid"] == 0
        and binding_file["stat"]["mode"] == "0400"
        and binding_file["stat"]["nlink"] == 1,
        "worker binding changed",
    )
    p38b.p37c._verify_control_sets(
        inputs["control_sets"], policy, action, producer["skill"]["digest"], grants
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
    p38b._verify_coherent_action(value["cases"]["coherent_consumed"], context)
    p38b.p37c._verify_secrets(value["secret_checks"], value["cases"])
    return context


def _verify_bindings(
    value: Mapping[str, Any],
    acquisition: Mapping[str, Any],
    action: Mapping[str, Any],
) -> None:
    transaction = acquisition["transaction"]
    checks = {
        "active_record_reused_by_runtime",
        "bounded_depth_one_two_file_tree_exact",
        "bounded_two_file_tree_exact",
        "cas_unchanged_through_runtime",
        "coordinator_state_result_exact",
        "flat_tree_stable_through_action",
        "fresh_source_request_exact",
        "installed_files_projected_exact",
        "live_quarantine_source_exact",
        "nested_directory_custody_exact",
        "nested_projection_stable_through_action",
        "nested_tree_stable_through_action",
        "network_disconnected_before_runtime",
        "network_remained_disconnected",
        "one_coherent_action_completed",
        "projection_stable_through_action",
        "skill_md_remains_producer_tree_entry",
        "skill_reused_by_runtime",
        "source_blob_installed_exact",
        "source_files_installed_exact",
        "transaction_reused_by_runtime",
    }
    _expect(
        set(value)
        == {
            "checks",
            "context_id",
            "directories",
            "manifest_digest",
            "projected_tree",
            "protected_tree",
            "skill_digest",
            "source_request",
            "transaction_digest",
            "tree_digest",
            "tree_entries",
            "tree_entry",
        }
        and set(value["checks"]) == checks
        and all(result is True for result in value["checks"].values())
        and value["context_id"] == transaction["context_id"]
        and value["manifest_digest"] == transaction["manifest_digest"]
        and value["transaction_digest"] == canonical_digest(transaction)
        and value["tree_digest"] == _TREE_DIGEST
        and value["skill_digest"] == _TREE_ENTRIES[0]["digest"]
        and value["directories"] == list(_DIRECTORIES)
        and canonical_json(value["tree_entries"]) == canonical_json(_TREE_ENTRIES)
        and canonical_json(value["tree_entry"]) == canonical_json(_TREE_ENTRIES[0])
        and value["source_request"] == _SOURCE_REQUEST
        and action["producer"]["transaction"] == transaction
        and action["producer"]["directories"] == list(_DIRECTORIES)
        and canonical_json(value["protected_tree"])
        == canonical_json(
            {
                "after_action": acquisition["tree"],
                "before_action": acquisition["tree"],
            }
        )
        and canonical_json(acquisition["tree"])
        == canonical_json(action["producer"]["protected_tree"])
        and canonical_json(value["projected_tree"])
        == canonical_json(
            {
                "after_action": action["producer"]["projected_tree"],
                "before_action": action["producer"]["projected_tree"],
            }
        ),
        "outer depth-one acquisition/action bindings changed",
    )


def _verify_network(
    document: Mapping[str, Any], acquisition: Mapping[str, Any]
) -> None:
    network = acquisition["network"]
    marker_specs = {
        "acquisition_complete_marker": (
            {
                "schema": "aragorn/p38d-acquisition-complete-marker/v1",
                "status": "ACQUISITION_COMPLETE",
            },
            "/run/aragorn-p38d-acquisition-complete",
            {
                "schema": "aragorn/p38c-acquisition-complete-marker/v1",
                "status": "ACQUISITION_COMPLETE",
            },
            "/run/aragorn-p38c-acquisition-complete",
        ),
        "disconnected_marker": (
            {
                "disconnected": True,
                "schema": "aragorn/p38d-network-disconnected-marker/v1",
            },
            "/run/aragorn-p38d-network-disconnected",
            {
                "disconnected": True,
                "schema": "aragorn/p38c-network-disconnected-marker/v1",
            },
            "/run/aragorn-p38c-network-disconnected",
        ),
    }
    legacy = _snapshot(network)
    for name, (expected, path, parent_expected, parent_path) in marker_specs.items():
        marker = network[name]
        raw = p38b._verify_bounded_file(marker["file"])
        _expect(
            marker["document"] == expected
            and marker["file"]["path"] == path
            and raw == canonical_json(expected) + b"\n",
            "network marker changed",
        )
        parent_raw = canonical_json(parent_expected) + b"\n"
        legacy[name]["document"] = parent_expected
        legacy[name]["file"].update(
            {
                "base64": base64.b64encode(parent_raw).decode("ascii"),
                "bytes": len(parent_raw),
                "digest": _raw_digest(parent_raw),
                "path": parent_path,
            }
        )
        legacy[name]["file"]["stat"].update(
            {"path": parent_path, "size": len(parent_raw)}
        )
    p38c._verify_network(document, {**acquisition, "network": legacy})


def _verify_custody_windows(document: Mapping[str, Any]) -> None:
    acquisition = document["acquisition"]
    action = document["action"]
    acquisition_started_ns = _iso_ns(acquisition["timing"]["started_at"])
    acquisition_completed_ns = _iso_ns(acquisition["timing"]["completed_at"])
    action_recorded_ns = _iso_ns(action["recorded_at"])
    outer_recorded_ns = _iso_ns(document["recorded_at"])
    _expect(
        acquisition_started_ns
        < acquisition_completed_ns
        < action_recorded_ns
        <= outer_recorded_ns,
        "acquisition/action recorded window changed",
    )

    quarantine = acquisition["quarantine"]
    protected = acquisition["protected"]
    cas_root = quarantine["cas_before_runtime"]["root"]
    credential = protected["service_receipt"]["request_authority"]["credential"]
    version = protected["version"]
    link = protected["active_link"]
    state_stat = acquisition["coordinator"]["state"]["file"]["stat"]
    tree_members = [
        *protected["tree"]["directories"].values(),
        *(record["stat"] for record in protected["tree"]["files"].values()),
    ]
    journal_ns = (
        int(protected["service_journal_identity"]["realtime_timestamp"]) * 1_000
    )
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
        and all(
            version["mtime_ns"]
            <= member["mtime_ns"]
            <= member["ctime_ns"]
            <= version["ctime_ns"]
            for member in tree_members
        )
        and version["ctime_ns"]
        <= link["mtime_ns"]
        == link["ctime_ns"]
        <= journal_ns
        <= state_stat["mtime_ns"]
        <= state_stat["ctime_ns"]
        <= acquisition_completed_ns,
        "acquisition custody chronology changed",
    )
    acquisition_records = [
        *_timed_records(quarantine["cas_before_runtime"]),
        *_timed_records(quarantine["cas_after_runtime"]),
        *_timed_records(protected),
        *_timed_records(acquisition["coordinator"]["state"]),
    ]
    _expect(
        len(acquisition_records) == 33
        and all(
            _inside_window(record, acquisition_started_ns, acquisition_completed_ns)
            for record in acquisition_records
        ),
        "acquisition custody timestamp escaped its window",
    )

    inputs = action["inputs"]
    action_records = [
        *_timed_records(action["cases"]),
        *_timed_records(inputs["grant_source"]),
        *_timed_records(inputs["short_grant"]["source"]),
        *_timed_records(inputs["producer"]["projected_tree"]),
    ]
    _expect(
        len(action_records) == 33
        and all(
            _inside_window(record, acquisition_completed_ns, action_recorded_ns)
            for record in action_records
        ),
        "runtime action record/state timestamp escaped its window",
    )


def _timed_records(value: Any) -> list[Mapping[str, Any]]:
    records: list[Mapping[str, Any]] = []

    def walk(child: Any) -> None:
        if isinstance(child, Mapping):
            if {"mtime_ns", "ctime_ns"}.issubset(child):
                records.append(child)
            for nested in child.values():
                walk(nested)
        elif isinstance(child, list):
            for nested in child:
                walk(nested)

    walk(value)
    return records


def _inside_window(record: Mapping[str, Any], start_ns: int, end_ns: int) -> bool:
    mtime_ns = record["mtime_ns"]
    ctime_ns = record["ctime_ns"]
    return (
        isinstance(mtime_ns, int)
        and not isinstance(mtime_ns, bool)
        and isinstance(ctime_ns, int)
        and not isinstance(ctime_ns, bool)
        and start_ns <= mtime_ns <= ctime_ns <= end_ns
    )


def _iso_ns(value: str) -> int:
    parsed = p38b._time(value)
    return int(parsed.timestamp()) * 1_000_000_000 + parsed.microsecond * 1_000


def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    return p38c._snapshot(value)


def _raw_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _expect(condition: Any, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(message)
