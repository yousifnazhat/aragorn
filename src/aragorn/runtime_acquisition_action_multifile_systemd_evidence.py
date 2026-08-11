"""Verify the bounded P3.8c two-file acquisition-to-action observation."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import runtime_acquisition_action_systemd_evidence as p38b
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest, canonical_json

_SCHEMA = "aragorn/runtime-acquisition-action-multifile-systemd-observation/v1"
_AUTHORITY = (
    "BOUNDED_LIVE_COORDINATOR_TWO_FILE_ACQUISITION_TO_RUNTIME_ACTION_OBSERVATION_"
    "ONLY_NOT_VERIFIED_RUN_EDR_INSTALLER_RELEASE_AUTHORITY"
)
_RETAINED_PATH = (
    "benchmark/evidence/runtime-acquisition-action-multifile-systemd-composition-"
    "p3-8c-2026-08-11.json"
)
_EVIDENCE_BYTES = 546_216
_EVIDENCE_RAW_DIGEST = (
    "sha256:5238310228e0116f77e15feaf7be735b454650cbae715cc6ee3452b1b7dff891"
)
_EVIDENCE_DIGEST = (
    "sha256:c8fa91e73954b7535ab4393728be41abe1c125b6cc31af6c3b93acf4021b03e0"
)
_RECORDED_AT = "2026-08-11T09:12:23.870632Z"
_SOURCE_COMMIT = "7897951c6e9421f5f6ddb947976b1a5d8a9553d0"
_PARENT_IMAGE = p38b._CHILD_IMAGE
_CHILD_IMAGE = "sha256:0f028d91f2215e6225bc4f5a30128edc56119cf9e2886b106bf18eb37f50fccb"
_TREE_DIGEST = "sha256:c3e6b4db9b149d219cd714ecabd94806c41c5a4811fdac9299f339e0bfca5d34"
_TOP_LEVEL = p38b._TOP_LEVEL
_P38B_RECEIPT_PATH = (
    "benchmark/receipts/phase3-runtime-acquisition-action-systemd-"
    "qualification-v1-2026-08-11.json"
)
_P38B_RECEIPT_BYTES = 7_738
_P38B_RECEIPT_RAW_DIGEST = (
    "sha256:53f8c2093ee5556801e314f4eb7d7af8933c9eee25aa1a4bcd8a89816d8b23ea"
)
_P38B_RECEIPT_DIGEST = (
    "sha256:cb2ca3426649d047b1519a465378051631d4f0c916d4f68ceacd2a0ce0bd4780"
)
_P38B_VERIFIER_DIGEST = (
    "sha256:3b8b5214bed875836012ed5cefd82f36e1a926218992b818a252883801b2f133"
)
_SECTION_DIGESTS = {
    "acquisition": "sha256:4f302c0922c17da3a26077c8e015f9ada119c1e37d74afc540a8eeba9faf563d",
    "action": "sha256:7de90e3ab4900932443e168177451d540ce209df775620303c2cb14b945978ee",
    "artifacts": "sha256:2841376055401a133fdf1d5c0d4985e67f99e59c1f539de186c012da5e50a137",
    "bindings": "sha256:58082f6fcfae3b552cc70f1bd56e2b343d011f6e84e6ceba05de01239c419609",
    "harness": "sha256:37ed5b1d0bd8be7e1104ed8dfed4b65f843e6f7c3047326e2ab34d56ad82a593",
}
_ACQUISITION_ENVELOPE_DIGEST = (
    "sha256:4f302c0922c17da3a26077c8e015f9ada119c1e37d74afc540a8eeba9faf563d"
)
_ACTION_ENVELOPE_DIGEST = (
    "sha256:7de90e3ab4900932443e168177451d540ce209df775620303c2cb14b945978ee"
)
_HARNESS_DIGEST = (
    "sha256:47432bcf8ffd9d1d4b8df10affc5437b9cfbd1de514a7060260036fd24d58eac"
)
_IMAGE_LINEAGE_DIGEST = (
    "sha256:ffd3126148f4afc129fb0a80a80311216529b62d0379d13d59a476e68771bcaf"
)
_ACTION_CASE_DIGESTS = {
    "coherent_consumed": "sha256:bbeaad242e9d88e8ee82c14b49b670503f32f7502dc42120d1648bf627b1f071",
    "expired_fail_stop": "sha256:83fca1289f6f564b293340667af6ff8410cb3cb2a61adb3a26faf2ebf861913d",
    "full_activation": "sha256:42f1452c9a573ab572d1633277b6e5899b0934c032bb1296f7bbcd062a86c9e1",
    "terminal_archive_rotation": "sha256:239281258c2e8645f9c85798e8277e645897f59eeb170084113d4ae3a8e7483d",
}
_COLLECTOR_DIGEST = (
    "sha256:b2f95dcc3c3e0a56065c54ab18bb69bfaacaf96831b4ed1612edec7f387c2338"
)
_OVERLAY_DIGEST = (
    "sha256:d2e279cfe948c4409406bef6ffed014c46190d0525f796b5fcfb235b56e8683f"
)
_OVERLAY_CLOSURE_DIGEST = (
    "sha256:fda45a16d5be976151d2c6b4bcfeec1bfe6f7ed0c38d994dd4ca717f1a4b3de4"
)
_ACTION_ARTIFACTS_PROJECTION_DIGEST = (
    "sha256:a85d1929cb093af7574729c090d52c791b0909cb8af538174791eb87720c353c"
)
_GATEWAY_CONFIG_DIGEST = (
    "sha256:3b98cb58a93799f666d55c80fc8f84611203035077b2fa72d3d6251e01c492f2"
)
_TRANSACTION_DIGEST = (
    "sha256:abceb6a647c754b66a6586d44fd0d1b62e22cfdda917349d588123dc105be5b7"
)
_SERVICE_RECEIPT_DIGEST = (
    "sha256:cd39db5fd5fcff80887187fb6f7aa243600247e9fe52336a8ca512b7f81ea99d"
)
_COORDINATOR_RESULT_DIGEST = (
    "sha256:c3fa7349dd1f5ee3d5f3aed38c72e8a56841d96530363941077cde6c9694d769"
)
_COORDINATOR_STATE_DIGEST = (
    "sha256:60698e65a0e5e5f0184a88bf33f685ab7ddbe545f41d01144ad18400ecf39f78"
)
_QUARANTINE_RECEIPT_DIGEST = (
    "sha256:ef21f3bb3df6bb3629814c1b2aa72d3363a3e7ddab613b63cbc4dc7358b8e24c"
)
_SOURCE_REQUEST = {
    "commit": "f57638a74759376871509ccf080e606f62052f1b",
    "owner": "obra",
    "repository": "superpowers",
    "schema": "aragorn/github-gateway-request/v1",
    "skill_path": "skills/requesting-code-review",
}
_TREE_ENTRIES = [
    {
        "digest": "sha256:1c9e975642c859c407bc4bbc9c06a171bf9ff88267300def1e02f46047ca5ad9",
        "executable": False,
        "path": "SKILL.md",
        "size": 2_712,
    },
    {
        "digest": "sha256:7f5328dca12cb200005ae9d4386f63a9b0acb735ece57f82db206b4a3189ccae",
        "executable": False,
        "path": "code-reviewer.md",
        "size": 3_385,
    },
]

_LIMITATIONS = [
    "ADAPTED_PYTHON_3_12_CURRENT_RELEASE_NOT_RETAINED_PHASE1_RELEASE_IDENTITY",
    "ONE_LIVE_PUBLIC_GITHUB_COMMIT_AND_EXACTLY_TWO_FILE_FLAT_SKILL_ONLY",
    "FLAT_TREE_ONLY_NESTED_SKILL_ASSETS_NOT_QUALIFIED",
    "ONE_EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_ACTION_ONLY",
    "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "SYSTEMD_252_CGROUP_AND_DOCKER_DNS_ADAPTERS_ARE_FIXTURE_ONLY",
    "NETWORK_DISCONNECTION_IS_WRAPPER_CONTROLLED_AND_PROBE_REVERIFIED",
    "TWO_SOURCE_FILES_ARE_BOUND_TO_THE_ACTION_WITHOUT_SEMANTIC_CAUSATION_AUTHORITY",
    "P3_7C_RUNTIME_FLOW_IS_REUSED_WITHOUT_PROMOTING_ITS_PARENT_QUALIFICATION",
    "NO_AGGREGATE_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
]
_DECISION = {
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
    "status": "P3_8C_OBSERVED_NOT_VERIFIED",
}
_QUALIFICATION_LIMITATIONS = [
    *_LIMITATIONS[:-1],
    "QUARANTINE_CAS_METADATA_AND_TWO_FILE_BYTES_RETAINED_NOT_FULL_NON_SKILL_BLOB_REPLAY",
    "PROVIDER_AND_OPENCLAW_SESSION_RAW_BYTES_NOT_RETAINED",
    "TRACE_PROVES_ONE_ROUTE_CONNECT_WITHOUT_RETRY_NOT_APPLICATION_SEND_COUNT",
    "PYTHON_STDLIB_AND_DYNAMIC_VERIFIER_DEPENDENCY_CLOSURE_NOT_PINNED",
    _LIMITATIONS[-1],
]
_QUALIFICATION_DECISION = {
    "aggregate_gate_eligible": False,
    "bounded_live_acquisition_action_evidence_eligible": True,
    "bounded_two_file_tree_verified": True,
    "edr_claim_eligible": False,
    "installer_authority_eligible": False,
    "live_same_custody_install_to_action_verified": True,
    "network_disconnected_before_runtime_verified": True,
    "one_coherent_allow_created_consumed_action_verified": True,
    "parent_p3_8b_unchanged": True,
    "phase3_exit_eligible": False,
    "public_release_eligible": False,
    "qualified_pair_retained_evidence_eligible": True,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "same_phase1_release_identity": False,
    "semantic_skill_causation_established": False,
    "source_observation_unchanged": True,
    "source_observation_verified": True,
    "status": "P3_8C_BOUNDED_TWO_FILE_PASS",
}


def verify_runtime_acquisition_action_multifile_systemd_evidence(
    document: Mapping[str, Any],
    p38b_observation: Mapping[str, Any],
    p37c_observation: Mapping[str, Any],
    p37b_observation: Mapping[str, Any],
    p36b_observation: Mapping[str, Any],
    p37b_receipt: Mapping[str, Any],
    p37c_receipt: Mapping[str, Any],
    p38b_receipt: Mapping[str, Any],
    *,
    expected_digest: str | None,
) -> None:
    """Replay the exact P3.8c observation without promoting broader authority."""

    try:
        _expect(expected_digest == _EVIDENCE_DIGEST, "retained digest pin changed")
        _expect(
            not p38b.p37c.parent_verifier._contains_float(document), "float is invalid"
        )
        (
            document,
            p38b_observation,
            p37c_observation,
            p37b_observation,
            p36b_observation,
            p37b_receipt,
            p37c_receipt,
            p38b_receipt,
        ) = (
            _snapshot(value)
            for value in (
                document,
                p38b_observation,
                p37c_observation,
                p37b_observation,
                p36b_observation,
                p37b_receipt,
                p37c_receipt,
                p38b_receipt,
            )
        )
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
        _verify_parent(
            p38b_observation,
            p37c_observation,
            p37b_observation,
            p36b_observation,
            p37b_receipt,
            p37c_receipt,
            p38b_receipt,
        )
        _verify_observation(document, p37c_observation)
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
            f"invalid runtime acquisition action multifile systemd evidence: {exc}"
        ) from exc


def runtime_acquisition_action_multifile_systemd_qualification(
    document: Mapping[str, Any],
    p38b_observation: Mapping[str, Any],
    p37c_observation: Mapping[str, Any],
    p37b_observation: Mapping[str, Any],
    p36b_observation: Mapping[str, Any],
    p37b_receipt: Mapping[str, Any],
    p37c_receipt: Mapping[str, Any],
    p38b_receipt: Mapping[str, Any],
    *,
    expected_digest: str | None,
    implementation_digest: str | None = None,
) -> dict[str, Any]:
    """Return the deterministic bounded P3.8c qualification."""

    try:
        values = tuple(
            _snapshot(value)
            for value in (
                document,
                p38b_observation,
                p37c_observation,
                p37b_observation,
                p36b_observation,
                p37b_receipt,
                p37c_receipt,
                p38b_receipt,
            )
        )
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid runtime acquisition action multifile systemd evidence: {exc}"
        ) from exc
    verify_runtime_acquisition_action_multifile_systemd_evidence(
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
            "SEMANTICALLY_REPLAY_VERIFIED_PINNED_LIVE_TWO_FILE_ACQUISITION_TO_"
            "ONE_COHERENT_RUNTIME_ACTION"
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
                    "bytes": p38b._EVIDENCE_BYTES,
                    "canonical_digest": p38b._EVIDENCE_DIGEST,
                    "path": p38b._RETAINED_PATH,
                    "raw_digest": p38b._EVIDENCE_RAW_DIGEST,
                },
                "receipt": {
                    "bytes": _P38B_RECEIPT_BYTES,
                    "canonical_digest": _P38B_RECEIPT_DIGEST,
                    "path": _P38B_RECEIPT_PATH,
                    "raw_digest": _P38B_RECEIPT_RAW_DIGEST,
                },
            },
            "implementation": {
                "p38b_verifier_digest": _P38B_VERIFIER_DIGEST,
                "verifier_implementation_digest": verifier_digest,
            },
            "acquisition": {
                "context_id": transaction["context_id"],
                "manifest_digest": transaction["manifest_digest"],
                "source_request": dict(acquisition["source_request"]),
                "tree_digest": transaction["tree_digest"],
            },
            "two_file_tree": {
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
            "live_two_file_acquisition": {
                "file_count": acquisition["quarantine"]["receipt"]["file_count"],
                "status": "PASS",
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
        "schema": (
            "aragorn/runtime-acquisition-action-multifile-systemd-qualification/v1"
        ),
        "source_recorded_at": document["recorded_at"],
    }


def _verify_parent(*args: Mapping[str, Any]) -> None:
    expected = p38b.runtime_acquisition_action_systemd_qualification(
        *args[:-1],
        expected_digest=p38b._EVIDENCE_DIGEST,
        implementation_digest=_P38B_VERIFIER_DIGEST,
    )
    p38b._require_receipt(
        args[-1],
        expected,
        digest=_P38B_RECEIPT_DIGEST,
        raw_digest=_P38B_RECEIPT_RAW_DIGEST,
        size=_P38B_RECEIPT_BYTES,
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
            "files": 197,
            "raw": 136,
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
            "p3_8c_overlay",
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
    collector = value["collector"]
    _expect(
        set(collector) == {"capture_recipe", "dockerfile", "probe"}
        and canonical_digest(collector) == _COLLECTOR_DIGEST,
        "collector closure changed",
    )
    for name, record in collector.items():
        p38b.p37c._verify_file(record)
        _expect(
            record["path"]
            == {
                "capture_recipe": "/src/scripts/capture_runtime_acquisition_action_multifile_systemd.sh",
                "dockerfile": "/src/benchmark/runtime-acquisition-action-multifile-systemd/Dockerfile",
                "probe": "/src/scripts/runtime_acquisition_action_multifile_systemd_probe.py",
            }[name]
            and record["stat"]["uid"] == record["stat"]["gid"] == 0
            and record["stat"]["mode"] == ("0444" if name == "dockerfile" else "0555"),
            "collector custody changed",
        )
    overlay = value["p3_8c_overlay"]
    _expect(
        set(overlay)
        == {
            "build_inputs",
            "installed",
            "installed_closure",
            "installed_closure_digest",
        }
        and canonical_digest(overlay) == _OVERLAY_DIGEST,
        "overlay changed",
    )
    expected = {
        "acquire.py": "sha256:56942e7c1b10c58f265615c8b7abf3f199c7f98bf016be50eb6d3a98d2bd0f8c",
        "cas.py": "sha256:c5642f910ac4b2d6172a59a02105b359cb43d3a2f2e2240368229d3436ad4859",
        "runtime_active_skill_lineage.py": "sha256:7f5fc7aa979efd0a719904d14b2d8576b80af302572882de90dca464291db726",
        "runtime_process_profile.py": "sha256:a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68",
        "activate-runtime-action-worker-host.sh": "sha256:466261b94b832da010a2f27896335731cfcaeb3a87d8c15767b80c6aceb752bb",
    }
    closure = []
    _expect(
        [pair["name"] for pair in overlay["installed"]] == list(expected),
        "overlay inventory changed",
    )
    for pair in overlay["installed"]:
        _expect(set(pair) == {"installed", "name", "source"}, "overlay pair changed")
        source, installed = pair["source"], pair["installed"]
        p38b.p37c._verify_file(source)
        p38b.p37c._verify_file(installed)
        _expect(
            source["digest"] == installed["digest"] == expected[pair["name"]]
            and source["bytes"] == installed["bytes"]
            and source["stat"]["mode"] in {"0444", "0555"}
            and installed["stat"]["mode"] in {"0644", "0755"},
            "overlay source/install join changed",
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
        canonical_json(closure) == canonical_json(overlay["installed_closure"])
        and canonical_digest(closure)
        == overlay["installed_closure_digest"]
        == _OVERLAY_CLOSURE_DIGEST,
        "overlay closure changed",
    )
    build_inputs = overlay["build_inputs"]
    _expect(
        {name: record["digest"] for name, record in build_inputs.items()}
        == {
            "install-runtime-action-worker-host.sh": "sha256:885441b628298629cc07d5c68e52b852864c6a755bc10d0e7e5de406f17b4748",
            "install-runtime-capability-host.sh": "sha256:6a7b4ec084b4dee8d974a0acab183f850be57e0acff30b616040687b307d28d9",
        },
        "overlay build inputs changed",
    )
    for record in build_inputs.values():
        p38b.p37c._verify_file(record)


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
        == "aragorn/runtime-acquisition-action-multifile-systemd-harness/v1"
        and harness["profile_label"] == "p3.8c"
        and harness["source_commit"] == _SOURCE_COMMIT
        and harness["parent_image_id"] == lineage["parent"]["id"] == _PARENT_IMAGE
        and harness["image_id"]
        == harness["run_image_reference"]
        == lineage["child"]["id"]
        == _CHILD_IMAGE
        and canonical_digest(lineage) == _IMAGE_LINEAGE_DIGEST
        and lineage["child"]["layers"]
        == [*lineage["parent"]["layers"], *lineage["added_layers"]]
        and len(lineage["added_layers"]) == 5
        and cgroup == f"0::/docker/{harness['container_id']}/init.scope\n".encode()
        and harness["host_config"]["privileged"] is True
        and harness["host_config"]["readonly_rootfs"] is False
        and harness["published_ports"] == {},
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


def _verify_tree(value: Mapping[str, Any], root_path: str) -> dict[str, bytes]:
    _expect(
        set(value) == {"entries", "files", "root", "tree_digest"}
        and canonical_json(value["entries"]) == canonical_json(_TREE_ENTRIES)
        and value["tree_digest"] == canonical_digest(value["entries"]) == _TREE_DIGEST
        and set(value["files"]) == {entry["path"] for entry in _TREE_ENTRIES},
        "two-file tree shape changed",
    )
    root = value["root"]
    p38b._verify_path_record(root)
    _expect(
        root["path"] == root_path
        and root["type"] == "directory"
        and root["uid"] == root["gid"] == 0
        and root["mode"] == "0555"
        and root["nlink"] == 2,
        "two-file tree root changed",
    )
    raw = {}
    identities = {(root["device"], root["inode"])}
    for entry in _TREE_ENTRIES:
        record = value["files"][entry["path"]]
        raw[entry["path"]] = p38b._verify_bounded_file(record)
        _expect(
            record["path"] == f"{root_path}/{entry['path']}"
            and record["bytes"] == entry["size"]
            and record["digest"] == entry["digest"]
            and record["stat"]["uid"] == record["stat"]["gid"] == 0
            and record["stat"]["mode"] == "0444"
            and record["stat"]["nlink"] == 1,
            "two-file tree entry changed",
        )
        identities.add((record["stat"]["device"], record["stat"]["inode"]))
        _expect(
            record["stat"]["device"] == root["device"],
            "two-file tree device changed",
        )
    _expect(len(identities) == 3, "two-file tree custody identity changed")
    return raw


def _verify_cas(value: Mapping[str, Any], namespace: str) -> set[tuple[int, int]]:
    closure = {
        "sha256:1c9e975642c859c407bc4bbc9c06a171bf9ff88267300def1e02f46047ca5ad9": 2_712,
        "sha256:2627b902af63875e2d5606c3e3ebcfbaef7db7e479d476ce5119d850d17798ca": 953,
        "sha256:388ef269d86fb1f80af7e5c5b50118178fbb6c567320ad6434b185d7c001e5de": 669,
        "sha256:7ba4d767aa1f8823264c627eb8824518cf923052d1c3549da0ca1a4c9b778de7": 548,
        "sha256:7f5328dca12cb200005ae9d4386f63a9b0acb735ece57f82db206b4a3189ccae": 3_385,
        "sha256:88d109688d25cc100ed30176e57e36247352a8bf017861895dfe181f67d61cde": 607,
        "sha256:919294be559f0a0e7d134bc64b379b8dabc0d5380629704946e5d9fc6d8ea68d": 80,
        "sha256:cec342f0eb849779d55d237866f972a1a021114007e3d04d98e567fc6a8bff0e": 956,
        "sha256:ef21f3bb3df6bb3629814c1b2aa72d3363a3e7ddab613b63cbc4dc7358b8e24c": 1_497,
        "sha256:f1dccd899402a284f8fe5a65247fafc29cf3459f248e9560f3f8c7835da1c00c": 1_152,
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
        and len(value["blobs"]) == len(identities) == 10
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
        and command["argv"]
        == [
            "/usr/local/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/aragorn-protected-install-coordinator.py",
            "submit",
            "install",
            "obra",
            "superpowers",
            _SOURCE_REQUEST["commit"],
            "skills/requesting-code-review",
        ]
        and command["exit_code"] == 0
        and json.loads(stdout) == result
        and stdout == canonical_json(result) + b"\n"
        and canonical_digest(result) == _COORDINATOR_RESULT_DIGEST
        and canonical_digest(state) == _COORDINATOR_STATE_DIGEST
        and result["schema"] == "aragorn/protected-install-coordinator-result/v1"
        and result["status"] == "COMPLETED_NOT_INSTALLER_AUTHORITY"
        and result["assurance"]
        == "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
        and result["installer_work_eligible"] is False
        and result["runtime_conformance_qualified"] is False
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
        and receipt["file_count"] == 2
        and receipt["request"] == _SOURCE_REQUEST
        and receipt["tree_digest"] == _TREE_DIGEST
        and canonical_digest(receipt) == _QUARANTINE_RECEIPT_DIGEST
        and quarantine["receipt_digest"]
        == canonical_digest(receipt)
        == result["quarantine_receipt_digest"],
        "quarantine receipt changed",
    )
    cas_identities = _verify_cas(
        quarantine["cas_before_runtime"], quarantine["namespace"]
    )
    _expect(
        cas_identities
        == _verify_cas(quarantine["cas_after_runtime"], quarantine["namespace"]),
        "CAS custody identity changed through runtime",
    )
    _expect(
        quarantine["cas_before_runtime"] == quarantine["cas_after_runtime"],
        "CAS changed through runtime",
    )
    source_files = {
        name: p38b.p37c._verify_raw(record)
        for name, record in quarantine["source_files"].items()
    }
    _expect(
        set(source_files) == {"SKILL.md", "code-reviewer.md"}
        and p38b.p37c._verify_raw(quarantine["source_skill"])
        == source_files["SKILL.md"]
        and all(
            quarantine["source_files"][entry["path"]]["digest"] == entry["digest"]
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
        and canonical_digest(transaction) == _TRANSACTION_DIGEST
        and canonical_json(protected["tree_entries"]) == canonical_json(_TREE_ENTRIES)
        and protected["tree_entry"] == _TREE_ENTRIES[0],
        "protected transaction changed",
    )
    version_path = f"/var/lib/aragorn-protected/skills/{transaction['version_path']}"
    installed = _verify_tree(protected["tree"], version_path)
    _expect(
        installed == source_files
        and protected["skill"] == protected["tree"]["files"]["SKILL.md"],
        "source/install bytes changed",
    )
    record = protected["record"]
    claim = protected["claim"]
    link = protected["active_link"]
    version = protected["version"]
    p38b._verify_path_record(link)
    p38b._verify_path_record(version)
    _expect(
        record["document"]["transaction"] == transaction
        and record["digest"]
        == record["raw_digest"]
        == record["file"]["digest"]
        == canonical_digest(record["document"])
        and claim["document"] == transaction
        and claim["digest"]
        == claim["raw_digest"]
        == claim["file"]["digest"]
        == canonical_digest(transaction)
        and canonical_digest(protected["service_receipt"]) == _SERVICE_RECEIPT_DIGEST
        and protected["service_receipt"]["transaction"] == transaction
        and protected["service_receipt"]["source"]["request"] == _SOURCE_REQUEST
        and record["file"]["path"]
        == "/var/lib/aragorn-protected/skills/.aragorn-active-runtime.json"
        and record["file"]["stat"]["uid"] == record["file"]["stat"]["gid"] == 0
        and record["file"]["stat"]["mode"] == "0444"
        and record["file"]["stat"]["nlink"] == 1
        and claim["file"]["path"]
        == (
            "/var/lib/aragorn-protected/skills/.aragorn-install-claims/"
            f"{transaction['context_id'][7:]}.json"
        )
        and claim["file"]["stat"]["uid"] == claim["file"]["stat"]["gid"] == 0
        and claim["file"]["stat"]["mode"] == "0400"
        and claim["file"]["stat"]["nlink"] == 1
        and link["type"] == "symlink"
        and link["path"] == "/var/lib/aragorn-protected/skills/aragorn-admitted"
        and link["target"] == transaction["version_path"]
        and link["uid"] == link["gid"] == 0
        and link["mode"] == "0777"
        and link["nlink"] == 1
        and link["size"] == len(link["target"].encode())
        and version == protected["tree"]["root"]
        and version["path"] == version_path
        and version["type"] == "directory"
        and version["uid"] == version["gid"] == 0
        and version["mode"] == "0555"
        and version["nlink"] == 2,
        "protected custody join changed",
    )
    protected_identities = {
        (record["file"]["stat"]["device"], record["file"]["stat"]["inode"]),
        (claim["file"]["stat"]["device"], claim["file"]["stat"]["inode"]),
        (link["device"], link["inode"]),
        (version["device"], version["inode"]),
        *(
            (item["stat"]["device"], item["stat"]["inode"])
            for item in protected["tree"]["files"].values()
        ),
    }
    _expect(
        len(protected_identities) == 6
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
        == "sha256:d0114d11a1b6cbd52d019acd1d9145c948c196751092c59a5d32a3071b07c6a9"
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
            "projected_skill",
            "projected_tree",
            "protected_tree",
            "record",
            "skill",
            "transaction",
            "tree_entries",
        }
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
    protected_raw = _verify_tree(
        producer["protected_tree"], acquisition["tree"]["root"]["path"]
    )
    projected_root = (
        "/var/lib/aragorn-agent-gateway/state/skills/requesting-code-review"
    )
    projected_raw = _verify_tree(producer["projected_tree"], projected_root)
    projected_identities = {
        (
            producer["projected_tree"]["root"]["device"],
            producer["projected_tree"]["root"]["inode"],
        ),
        *(
            (record["stat"]["device"], record["stat"]["inode"])
            for record in producer["projected_tree"]["files"].values()
        ),
    }
    _expect(
        protected_raw == projected_raw == acquisition["source_files"]
        and producer["projected_skill"]["path"] == f"{projected_root}/SKILL.md"
        and projected_identities.isdisjoint(acquisition["protected_identities"])
        and projected_identities.isdisjoint(acquisition["cas_identities"]),
        "action two-file projection changed",
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
        grant = p38b.parse_runtime_capability_grant(canonical_json(wrapper["document"]))
        _expect(
            wrapper["digest"] == canonical_digest(grant)
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
        "bounded_two_file_tree_exact",
        "cas_unchanged_through_runtime",
        "coordinator_state_result_exact",
        "flat_tree_stable_through_action",
        "fresh_source_request_exact",
        "installed_files_projected_exact",
        "live_quarantine_source_exact",
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
        and canonical_json(value["tree_entries"]) == canonical_json(_TREE_ENTRIES)
        and canonical_json(value["tree_entry"]) == canonical_json(_TREE_ENTRIES[0])
        and value["source_request"] == _SOURCE_REQUEST
        and action["producer"]["transaction"] == transaction
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
        "outer two-file acquisition/action bindings changed",
    )


def _verify_network(
    document: Mapping[str, Any], acquisition: Mapping[str, Any]
) -> None:
    network = acquisition["network"]
    marker_specs = {
        "acquisition_complete_marker": (
            {
                "schema": "aragorn/p38c-acquisition-complete-marker/v1",
                "status": "ACQUISITION_COMPLETE",
            },
            "/run/aragorn-p38c-acquisition-complete",
            {
                "schema": "aragorn/p38b-acquisition-complete-marker/v1",
                "status": "ACQUISITION_COMPLETE",
            },
            "/run/aragorn-p38b-acquisition-complete",
        ),
        "disconnected_marker": (
            {
                "disconnected": True,
                "schema": "aragorn/p38c-network-disconnected-marker/v1",
            },
            "/run/aragorn-p38c-network-disconnected",
            {
                "disconnected": True,
                "schema": "aragorn/p38b-network-disconnected-marker/v1",
            },
            "/run/aragorn-p38b-network-disconnected",
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
    p38b._verify_network_order(
        document,
        {**acquisition, "network": legacy},
        {},
    )


def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    return p38b._snapshot(value)


def _raw_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _expect(condition: Any, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(message)
