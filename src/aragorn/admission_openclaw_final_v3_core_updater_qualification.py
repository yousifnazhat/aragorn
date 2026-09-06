"""Qualify the exact retained core-updater denial, never a whole campaign."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import runpy
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from . import (
    admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture as semantic,
)
from . import admission_openclaw_final_v3_workshop_invalidation_subfixture as custody
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[2]
_ROUTE = "ADM-02/update/core-updater-plugin-replacement"
_ACTION = "core-updater-plugin-replacement"
_SOURCE = {
    "commit": "05192ef62e26a067bc8ef72b0c9d3d7d2813b201",
    "parent": "42a04052e5782f9a565817f831a72ce3f0611cd2",
    "tree": "7cc01233f33ec3d484c8dbce45d2a85e299bf513",
}
_RETENTION = {
    "commit": "4e72fa6278a4625fa7cda5735a3eff7f9271a8ce",
    "parent": _SOURCE["commit"],
    "tree": "99bb7018a6551250bb6b39c1d2b67579ab3579f0",
}
_EVIDENCE = {
    "bytes": 598_667,
    "canonical_bytes": 598_666,
    "canonical_digest": "sha256:888a50bf916c10ce03820c3e3ece76890fb9b19aaecd10ea602ada39bba17907",
    "digest": "sha256:4718a3bdaf5c9474e301ff8d825332a804119cc69a17888bc9fdbffba396dabc",
    "path": "benchmark/evidence/runtime-action-worker-final-combined-v3-route-core-updater-plugin-replacement-systemd-p3-final-2026-09-03.json",
}
_EVIDENCE_BLOB = "6ab96ff90f54cadb1647a84cfc9ac2ca1a7337e8"
_IMAGE = "sha256:1c75f0c37070aa5b702e134e6e6c830690f596891ce0f4fa389ea7515300ea17"
_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_INPUT_VOLUME = "aragorn-phase3-final-combined-v3-core-updater-plugin-replacement-route-input-6512"
_INPUT_ROOT = "/route-input/core-updater-plugin-replacement/"
_ELIGIBILITY_KEYS = custody._ELIGIBILITY_KEYS
# Filled only from the signed acquisition checkpoint; absent pins deny PASS.
_ACQUISITION: dict[str, Any] = {}
_ACQUISITION_RETENTION: dict[str, str] = {}
_ACQUISITION_BLOB = ""
_contract = custody.parent.v3_contract.contract
_git = custody.parent.v3_contract.config.base.legacy._git
_verify_commit = custody.parent.v3_contract.config.base._verify_commit


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(f"core-updater qualification: {label}")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _signed_record(commit: str, record: dict[str, Any]) -> bytes:
    """Rehash one exact tree entry; callers supply already bound records."""
    path = record["path"].removeprefix("/src/")
    _require(
        not path.startswith("/") and all(p not in {"", ".", ".."} for p in path.split("/")),
        "unsafe signed path",
    )
    entry = _git(["ls-tree", "-z", "--full-name", commit, "--", path])
    metadata, separator, returned = entry.partition(b"\t")
    fields = metadata.split()
    _require(
        separator == b"\t" and returned == path.encode() + b"\0"
        and len(fields) == 3 and fields[0] in {b"100644", b"100755"}
        and fields[1] == b"blob",
        "signed file membership changed",
    )
    return custody._read_signed_blob(
        _git, commit=commit, mode=fields[0].decode(), blob=fields[2].decode(),
        bytes_=record["bytes"], digest=record["digest"], path=path,
    )


def _load_original(store: CAS) -> dict[str, Any]:
    _require(
        Path(_git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve() == _ROOT
        and _git(["rev-parse", "--show-object-format"]).strip() == b"sha1",
        "qualification repository changed",
    )
    for identity in (_SOURCE, _RETENTION):
        _verify_commit(identity)
    custody_path = "src/aragorn/admission_openclaw_final_v3_workshop_invalidation_subfixture.py"
    custody_raw = _git(["show", f"{_SOURCE['commit']}:{custody_path}"])
    _require(
        Path(custody.__file__).resolve() == _ROOT / custody_path
        and Path(custody.__file__).read_bytes() == custody_raw,
        "custody verifier dependency changed",
    )
    custody._verify_dependencies()
    _require(
        _git(["diff-tree", "--no-commit-id", "--name-status", "-r", _RETENTION["commit"]])
        == f"A\t{_EVIDENCE['path']}\n".encode(),
        "retention is not evidence-only",
    )
    retained = custody._read_signed_blob(
        _git, commit=_RETENTION["commit"], mode="100644", blob=_EVIDENCE_BLOB,
        bytes_=_EVIDENCE["bytes"], digest=_EVIDENCE["digest"], path=_EVIDENCE["path"],
    )
    raw = _contract._read_blob(store, _EVIDENCE, "core-updater observation")
    _require(raw == retained, "CAS differs from signed evidence")
    return _contract._load_canonical_json(raw, _EVIDENCE, "core-updater observation")


def _decode(record: dict[str, Any], *, canonical: bool = False) -> dict[str, Any]:
    raw = base64.b64decode(record["base64"], validate=True)
    _require(len(raw) == record["bytes"] and _digest(raw) == record["digest"], "raw bytes changed")
    value = json.loads(
        raw, object_pairs_hook=_contract._reject_duplicates,
        parse_constant=_contract._reject_constant,
    )
    _require(type(value) is dict, "raw document is not an object")
    if canonical:
        _require(raw == canonical_json(value), "raw JSON is not canonical")
    if "canonical_digest" in record:
        _require(canonical_digest(value) == record["canonical_digest"], "canonical digest changed")
    return value


def _file_record(record: dict[str, Any], *, mode: str) -> None:
    stat = record["stat"]
    _require(
        stat["uid"] == 0 and stat["gid"] == 0 and stat["nlink"] == 1
        and stat["mode"] == mode and stat["type"] == "file"
        and stat["size"] == record["bytes"],
        "root-owned file custody changed",
    )


def _verify_capture(evidence: dict[str, Any]) -> dict[str, Any]:
    # ponytail: one exact signed capture, not a reusable arbitrary-capture verifier.
    # A new capture needs new reviewed pins; the campaign backend owns generalization.
    _require(canonical_digest(evidence) == _EVIDENCE["canonical_digest"], "exact capture changed")
    custody.parent.v3_contract.config._verify_no_positive_eligibility(evidence)
    _require(
        evidence["schema"] == "aragorn/runtime-action-worker-final-combined-v3-core-updater-plugin-replacement-systemd-observation/v1"
        and evidence["route_id"] == _ROUTE
        and evidence["decision"]["route_observation_status"] == "OBSERVED"
        and evidence["decision"]["route_pass_count"] == 0
        and evidence["decision"]["route_fail_count"] == 0
        and evidence["decision"]["route_not_tested_count"] == 21,
        "raw envelope claim changed",
    )
    harness = evidence["harness"]
    host = harness["document"]
    composition = evidence["composition"]
    action = composition["action"]
    inherited = action["artifacts"]["final_combined_v3_workshop_proposal_apply"]
    _require(_decode(harness["file"], canonical=True) == host, "harness raw/document mismatch")
    _file_record(harness["file"], mode="0600")
    _require(
        harness["digest"] == harness["file"]["digest"]
        and action["harness"] == harness and host["source_commit"] == _SOURCE["commit"]
        and host["image_id"] == host["run_image_reference"] == _IMAGE
        and host["parent_image_id"] == custody._PARENT_IMAGE
        and host["schema"] == "aragorn/runtime-action-worker-final-combined-v3-core-updater-plugin-replacement-systemd-harness/v1"
        and host["host_config"]["network_mode"] == "none"
        and host["openclaw_runtime_mount"]["source"] == _VOLUME
        and host["openclaw_runtime_mount"]["rw"] is False
        and host["route_input_mount"]["source"] == _INPUT_VOLUME
        and host["route_input_mount"]["rw"] is False
        and host["route_input_volume_identity"]["labels"] == {
            "dev.aragorn.capture-owner": _SOURCE["commit"] + ":6512",
            "dev.aragorn.role": "final-combined-v3-core-updater-plugin-replacement-route-input",
            "dev.aragorn.source-commit": _SOURCE["commit"],
        },
        "dedicated harness binding changed",
    )
    lineage = host["image_lineage"]
    _require(
        lineage["child"]["id"] == _IMAGE and lineage["parent"]["id"] == custody._PARENT_IMAGE
        and lineage["child"]["layers"] == lineage["parent"]["layers"] + lineage["added_layers"],
        "image lineage changed",
    )
    signature = host["source_commit_verification"]
    commit = signature["commit_object"]
    commit_raw = base64.b64decode(commit["base64"], validate=True)
    _require(
        signature["command"] == ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        and signature["exit_code"] == 0 and len(commit_raw) == commit["bytes"]
        and _digest(commit_raw) == commit["digest"]
        and commit_raw == _git(["cat-file", "commit", _SOURCE["commit"]]),
        "captured signature does not join signed source",
    )
    custody.parent.v3_contract.parent._verify_contract_artifacts(inherited)
    profile = inherited["profile"]["document"]
    _require(
        composition["profile"]["before"] == composition["profile"]["after"]
        and composition["profile"]["before"]["document"] == profile
        and composition["profile"]["before"]["outcomes"] == {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        and action["inputs"]["gateway_config"] == inherited["config"]["document"]
        and action["runtime"]["tree"] == custody.parent.v3_contract.config._RUNTIME_TREE
        and composition["bindings"]["runtime_volume"] == _VOLUME,
        "frozen runtime/profile binding changed",
    )
    observation = evidence["route_observation"]
    document = _decode(observation["raw"])
    _require(document == observation["document"], "route raw/document mismatch")
    execution = observation["execution"]
    pid = observation["gateway_pid_binding"]["pid"]
    stack = observation["stack_before"]
    gateway = "aragorn-agent-gateway.service"
    process = stack["processes"][gateway]
    prerequisite = document["actions"][0]["prerequisites"]["gateway_process"]
    _require(
        type(pid) is int and pid > 0 and execution["exit_code"] == 0
        and execution["argv"] == [
            "nsenter", "--target", str(pid), "--mount", "--", "setpriv",
            "--reuid=992", "--regid=992", "--groups=992", "--inh-caps=-all",
            "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs",
            "/usr/local/bin/node", _INPUT_ROOT + "protected-core-updater-plugin-replacement-v3-probe.mjs",
            "--route-id", _ROUTE,
        ]
        and execution["effective_identity"] == {"gid": 992, "groups": [992], "uid": 992}
        and execution["stderr"] == {"bytes": 0, "digest": _digest(b""), "excerpt": ""}
        and process["pid"] == pid == stack["pids"][gateway] == prerequisite["pid"]
        and process["uids"] == process["gids"] == [992] * 4
        and process["capabilities_effective"] == "0000000000000000"
        and process["no_new_privileges"] == 1
        and prerequisite["hostname"] == host["container_id"][:12]
        and prerequisite["start_time_ticks"] == process["start_time_ticks"],
        "native unprivileged execution binding changed",
    )
    legacy = custody.parent.contract.base.legacy
    legacy._verify_stack_boundary(
        stack, trusted=action["boundaries"], container_id=host["container_id"],
        snapshot_before=execution["started_at"],
    )
    legacy._verify_gateway_listener(stack["gateway_listener"], stack["processes"])
    _require(
        legacy._parse_time(execution["started_at"])
        <= legacy._parse_time(document["recorded_at"])
        <= legacy._parse_time(execution["completed_at"])
        <= legacy._parse_time(evidence["recorded_at"]),
        "capture chronology changed",
    )
    _verify_materialization(evidence)
    return semantic.verify_openclaw_final_v3_core_updater_plugin_replacement_semantic_compatibility(document)


def _verify_materialization(evidence: dict[str, Any]) -> None:
    artifacts = evidence["source_artifacts"]
    dedicated = evidence["composition"]["action"]["artifacts"]["final_combined_v3_core_updater_plugin_replacement"]
    generated = {"materialized_v2_probe", "materialized_v2_proposal", "transformed_probe", "probe_bundle"}
    records = [value for name, value in artifacts.items() if name not in generated]
    records.extend(dedicated["collector"].values())
    records.append(dedicated["rebound_materializer"])
    records.extend(item["checked_in_source"] for item in dedicated["candidate_source"].values())
    records.append({
        "path": "/src/scripts/capture_runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd.sh",
        "bytes": 26_603,
        "digest": "sha256:a4f03cf2788f097d556be2b6ef93d758d6b12622a292a530784599d20b00ae96",
    })
    for record in records:
        if "stat" in record:
            _file_record(record, mode=record["stat"]["mode"])
        signed = _signed_record(_SOURCE["commit"], record)
        path = _ROOT / record["path"].removeprefix("/src/")
        # Generated runtime probes are handled below, never trusted as source files.
        _require(not path.is_symlink() and path.read_bytes() == signed, "capture source checkout drift")
    _require(
        Path(semantic.__file__).resolve() == (_ROOT / artifacts["semantic_verifier_source"]["path"].removeprefix("/src/")),
        "semantic verifier import changed",
    )
    custody.parent._verify_materialization()
    path = _ROOT / artifacts["dedicated_materializer"]["path"].removeprefix("/src/")
    materialize = runpy.run_path(str(path))["materialize_openclaw_final_v3_core_updater_plugin_replacement"]
    with TemporaryDirectory(prefix="aragorn-core-updater-qualification-") as temporary:
        output = Path(temporary) / "bundle"
        manifest = materialize(output)
        bundle = manifest["files"]
        _require(
            manifest["case_id"] == _ROUTE and bundle == artifacts["probe_bundle"]
            and bundle == evidence["route_observation"]["bundle"]
            and output.stat().st_mode & 0o777 == 0o555,
            "materialized bundle changed",
        )
        runtime = {
            "protected-core-updater-plugin-replacement-v3-probe.mjs": dedicated["probe"]["runtime"],
            "protected-route-action-probe.mjs": dedicated["delegated_probe"],
            "core-updater-plugin-replacement-audit-listener.mjs": dedicated["audit_listener"]["runtime"],
            **{f"candidate-source/{name}": value["runtime"] for name, value in dedicated["candidate_source"].items()},
        }
        _require(set(runtime) == {item["name"] for item in bundle}, "runtime bundle inventory changed")
        for item in bundle:
            file = output / item["name"]
            raw = file.read_bytes()
            record = runtime[item["name"]]
            _file_record(record, mode="0444")
            _require(
                not file.is_symlink() and file.stat().st_mode & 0o777 == 0o444
                and len(raw) == item["bytes"] == record["bytes"]
                and _digest(raw) == item["digest"] == record["digest"]
                and record["path"] == _INPUT_ROOT + item["name"],
                "generated/runtime bundle custody changed",
            )


def qualify_openclaw_final_v3_core_updater_subfixture(*, evidence_cas: CAS) -> dict[str, Any]:
    """Fail closed until signed native-module provenance is retained and joined."""
    try:
        evidence = _load_original(evidence_cas)
        semantics = _verify_capture(evidence)
        provenance, acquisition_binding = _verify_acquisition(evidence_cas, evidence)
    except AdmissionEvidenceError:
        raise
    except (AttributeError, binascii.Error, CASError, KeyError, IndexError, OSError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(f"invalid core-updater qualification: {exc}") from exc
    routes = [
        {"id": route, "status": "PASS" if route == _ROUTE else "NOT_TESTED"}
        for route in custody._ROUTES
    ]
    return {
        "schema": "aragorn/openclaw-final-v3-core-updater-route-qualification/v1",
        "assurance": "ONE_EXACT_SIGNED_DEDICATED_PRIVATE_V3_CORE_UPDATER_POLICY_DENIAL_ONLY",
        "bindings": {
            "observation": {**_EVIDENCE, "source": dict(_SOURCE), "retention": dict(_RETENTION)},
            "native_module_acquisition": acquisition_binding,
            "image": _IMAGE,
            "runtime_tree": dict(custody.parent.v3_contract.config._RUNTIME_TREE),
            "semantic_compatibility_digest": canonical_digest(semantics),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {"status": "PARTIAL_DYNAMIC_V3_ROUTE_COVERAGE", **{key: False for key in _ELIGIBILITY_KEYS}},
        "profile": {"name": custody._PROFILE, "counts": {"PASS": 1, "NOT_TESTED": 20}, "routes": routes},
        "route_semantics": {
            "dynamically_exercised_routes": [_ROUTE],
            "replacement_target_unchanged": True,
            "pass_basis": "SIGNED_DEDICATED_NATIVE_CORE_UPDATER_GIT_POLICY_DENIAL_BEFORE_REPLACEMENT",
            "native_provenance": provenance,
        },
        "capture": {"dedicated_route_container": True, "dedicated_route_volume": True, "cleanup_recipe_verified": True, "independent_host_destruction_attestation": False},
        "limitations": [
            "ONE_EXACT_CORE_UPDATER_POLICY_DENIAL_ROUTE_ONLY",
            "TWENTY_OTHER_V3_ROUTES_NOT_TESTED",
            "DEDICATED_CAPTURE_NOT_FINAL_CAMPAIGN_SUBFIXTURE_EVIDENCE",
            "POST_CAPTURE_READ_ONLY_NATIVE_MODULE_ACQUISITION_BOUND_BY_FULL_RUNTIME_TREE",
            "SELECTED_NATIVE_CALL_SITE_SUBSET_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
            "NO_DIRECT_POLICY_PROCESS_OR_FUNCTION_TRACE",
            "CLEANUP_RECIPE_NOT_INDEPENDENT_HOST_DESTRUCTION_ATTESTATION",
            "WRITABLE_CONFIG_COPY_USED_FOR_FAILURE_BOOKKEEPING_NO_ROLLBACK_CLAIM",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "SOURCE_TO_BINARY_REPRODUCIBILITY_NOT_INDEPENDENTLY_ATTESTED",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "source_recorded_at": evidence["recorded_at"],
    }


def _verify_acquisition(store: CAS, evidence: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    from . import admission_openclaw_final_v3_core_updater_provenance as native

    _require(bool(_ACQUISITION) and bool(_ACQUISITION_RETENTION), "signed native-module acquisition not yet retained")
    _verify_commit(_ACQUISITION_RETENTION)
    retained = custody._read_signed_blob(
        _git, commit=_ACQUISITION_RETENTION["commit"], mode="100644", blob=_ACQUISITION_BLOB,
        bytes_=_ACQUISITION["bytes"], digest=_ACQUISITION["digest"], path=_ACQUISITION["path"],
    )
    raw = _contract._read_blob(store, _ACQUISITION, "core-updater native module acquisition")
    _require(raw == retained, "native acquisition CAS differs from signed retention")
    acquired = _contract._load_canonical_json(raw, _ACQUISITION, "core-updater native module acquisition")
    semantic._verify_no_positive_eligibility(acquired)
    source = acquired["source"]
    _verify_commit(source)
    _require(
        _ACQUISITION_RETENTION["parent"] == source["commit"]
        and source["signature"] == _contract._SIGNATURE
        and _git(["diff-tree", "--no-commit-id", "--name-status", "-r", _ACQUISITION_RETENTION["commit"]])
        == f"A\t{_ACQUISITION['path']}\n".encode(),
        "native acquisition signature/retention changed",
    )
    script_path = "scripts/capture_openclaw_final_v3_core_updater_modules.py"
    _require(
        set(source["files"]) == {"acquisition", "acquisition_helpers", "runtime_tree_helper", "route_evidence"}
        and source["files"]["acquisition"]["path"] == script_path,
        "acquisition source inventory changed",
    )
    for name, record in source["files"].items():
        commit = _RETENTION["commit"] if name == "route_evidence" else source["commit"]
        signed = _signed_record(commit, record)
        path = _ROOT / record["path"]
        _require(not path.is_symlink() and path.read_bytes() == signed, "acquisition source checkout drift")
    namespace = runpy.run_path(str(_ROOT / script_path))
    live = acquired["acquisition"]
    _require(
        acquired["schema"] == namespace["_SCHEMA"]
        and acquired["original_route"] == {
            "route_id": _ROUTE, "recorded_at": evidence["recorded_at"], "capture_image_id": _IMAGE,
            "evidence": {key: _EVIDENCE[key] for key in ("path", "bytes", "digest")},
            "source_commit": _SOURCE["commit"], "retention_commit": _RETENTION["commit"],
        }
        and live["image"]["id"] == _IMAGE
        and {key: live["volume"][key] for key in namespace["_EXPECTED_VOLUME"]} == namespace["_EXPECTED_VOLUME"]
        and live["commands"]["acquisition"] == namespace["_command"]()
        and live["running_volume_users_before"] == live["running_volume_users_after"] == []
        and acquired["containment"] == namespace["_containment"](),
        "native acquisition containment or original-runtime join changed",
    )
    preflight = evidence["route_observation"]["document"]["core_updater_preflight"]
    observed = {
        item["path"]: item for item in (
            preflight["installed_index"]["writer_module"],
            preflight["trusted_policy_audit"]["diagnostic_module"],
        )
    }
    selected = {key: deepcopy(live[key]) for key in (
        "runtime_tree_before", "runtime_tree_after", "module_files", "runtime_tree_helper", "mounts",
    )}
    for record in selected["module_files"]:
        record.pop("observed_in_original_route")
    namespace["_validate_live"](selected, observed)
    _require(
        all(selected[key] == live[key] for key in selected)
        and live["runtime_tree_before"] == live["runtime_tree_after"] == evidence["composition"]["action"]["runtime"]["tree"]
        and custody.parent.contract.base.legacy._parse_time(acquired["recorded_at"])
        > custody.parent.contract.base.legacy._parse_time(evidence["recorded_at"]),
        "post-capture runtime-tree or module custody changed",
    )
    files = {record["path"]: base64.b64decode(record["content_base64"], validate=True) for record in live["module_files"]}
    provenance = native.verify_core_updater_native_provenance(files, evidence["route_observation"]["document"])
    binding = {
        **_ACQUISITION, "retention": dict(_ACQUISITION_RETENTION),
        "source": {key: source[key] for key in ("commit", "parent", "tree", "signature")},
        "native_provenance_verifier_digest": _digest(Path(native.__file__).read_bytes()),
    }
    return provenance, binding
