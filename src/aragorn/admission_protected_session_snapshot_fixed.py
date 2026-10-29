"""Route-only qualification for the fixed OpenClaw session snapshot consumer."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import tarfile
from collections.abc import Mapping
from io import BytesIO
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Any

from . import admission_protected_session_snapshot as parent
from . import admission_routes
from .admission_evidence import AdmissionEvidenceError, _read_exact, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/reload/session-snapshot-consumer"
_EVIDENCE_SCHEMA = "aragorn/openclaw-protected-session-snapshot-fixed-observation/v1"
_EVIDENCE_DIGEST = (
    "sha256:ab0d75eaf31c6dcc6350faa2cb5fc7d77e20d54b6f3d1232c104586bf00ad816"
)
_EVIDENCE_CANONICAL_DIGEST = (
    "sha256:76393aaccd3bbc0082c0e78bea21f019f0e4b7ed721e1a4cd36bd5472dd5dc0d"
)
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:db760abc5a9206009ac097788da3eb4126d4890cad6ec4e6c7ca84f41f57ea89"
)
_PROFILE_DIGEST = (
    "sha256:29276006af58552f6177e825a5562bd7d591f5f52e93e8de6fab58811f15bf99"
)
_PROFILE_CANONICAL_DIGEST = (
    "sha256:0b88918c204742a9d5ba2cfa45ce6f54234adbe2da397dfbacc603540e22209a"
)
_RUNTIME_LOCK_DIGEST = (
    "sha256:669639acd758bc7f749028bbef50e7a890fa355e7f8db9519f14ddc6602d9cd4"
)
_RUNTIME_LOCK_CANONICAL_DIGEST = (
    "sha256:5b7b49b7eec076895bff539a3e7fbec9b69f0d75efd476846444351700f53a96"
)
_HELPER_DIGEST = parent._HELPER_DIGEST
_PROBE_DIGEST = (
    "sha256:1efe13c3beb3ac2ff6fc1293aa64875c95424f1576a10b12943f0b875af223e2"
)
_MANIFEST_DIGEST = (
    "sha256:91bbabf89dc13edf4ee26cb6bef81c36ea2bc6eace8472a9301db88782b97de8"
)
_ARCHIVE_DIGEST = (
    "sha256:1b1d46970b237e300d32cbb227465438f7e872b42eac1a96fa295c58f7248c82"
)
_CONFIG_DIGEST = parent._CONFIG_DIGEST
_TARGET_DIGEST = parent._TARGET_DIGEST
_EVIDENCE_BYTES = 96_910
_MANIFEST_BYTES = 2_711
_ARCHIVE_BYTES = 336_256
_PROFILE_BYTES = 3_713
_RUNTIME_LOCK_BYTES = 3_742
_HELPER_BYTES = 13_609
_PROBE_BYTES = 41_345
_RESOLVER_SNAPSHOT_DIGEST = (
    "sha256:7b95d19d18fed24ab4eff23c96b233d6b03021344bd4b4f8136980bfca5ca8ab"
)
_SYSTEM_PROMPT_DIGEST = (
    "sha256:f60b30f53eebc7e29e7f3c18d4f0a7565426088e65fb5d7d43aa1c2470a207bc"
)
_MODULE_FILES_DIGEST = (
    "sha256:3f88eef08e6ef5b06fda23cff84613d239454ec9b1000bbe1ed2b62a5b3f7e36"
)
_FIXED_CLOSURE_PATHS = (
    "lib/node_modules/openclaw/dist/agent-command-DowjS4rA.js",
    "lib/node_modules/openclaw/dist/attempt-execution-BYfuRexC.js",
    "lib/node_modules/openclaw/dist/attempt.model-diagnostic-events-Dg8sP6iR.js",
    "lib/node_modules/openclaw/dist/embedded-agent-Dkb05T-e.js",
    "lib/node_modules/openclaw/dist/selection-weQvCGzP.js",
    "lib/node_modules/openclaw/dist/session-snapshot-CMKRWMg1.js",
    "lib/node_modules/openclaw/dist/session-snapshot-Bm-DN9wl.js",
    "lib/node_modules/openclaw/dist/session-store.runtime-DnJ24Mq_.js",
    "lib/node_modules/openclaw/dist/session-store.runtime.js",
    "lib/node_modules/openclaw/dist/skill-prompt-blobs-zJRX9N65.js",
    "lib/node_modules/openclaw/dist/store-CRMOBYMq.js",
    "lib/node_modules/openclaw/dist/system-prompt-config-BeuaroSf.js",
    "lib/node_modules/openclaw/dist/system-prompt-report-jSGxzBCq.js",
    "lib/node_modules/openclaw/dist/workspace-BKXau6p-.js",
)
_RUNTIME_TREE = {
    "algorithm": "aragorn/runtime-tree/v1",
    "entry_count": 45_860,
    "file_count": 45_841,
    "symlink_count": 19,
    "total_bytes": 369_417_908,
    "tree_digest": "sha256:4e866a250429632f5796d977554acbaabe6f30dbf837457e32022eacdb9152c1",
}
_LIMITATIONS = [
    "PRIVATE_FIXED_SOURCE_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "EXACT_PINNED_PROFILE_AND_SINGLE_CAPTURE_ONLY",
    "DIRECT_PINNED_COMPILED_REPLAY_PLUS_NATIVE_SESSION_PERSISTENCE_ONLY",
    "NATIVE_PROVIDER_REQUEST_BODY_NOT_OBSERVED",
    "NATIVE_SYSTEM_PROMPT_REPORT_NOT_PERSISTED",
    "FOURTEEN_SELECTED_COMPILED_ROUTE_MODULES_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
    "SOURCE_TO_BINARY_REPRODUCIBILITY_NOT_INDEPENDENTLY_ATTESTED",
    "TWENTY_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "RUN_01_AND_RUN_02_NOT_ESTABLISHED",
    "PHASE3_EXIT_EDR_AND_RELEASE_AUTHORITY_NOT_ESTABLISHED",
]


def verify_openclaw_protected_session_snapshot_fixed(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    runtime_lock: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> dict[str, Any]:
    """Qualify one fixed route without promoting the aggregate profile."""

    try:
        receipt = _snapshot(source_receipt)
        profile = _snapshot(route_profile)
        lock = _snapshot(runtime_lock)
        inventory = _snapshot(route_inventory)
        candidates = _snapshot(runtime_candidates)
        admission_routes.validate_openclaw_2026_7_1_route_inventory(
            inventory, candidates
        )
        _verify_profile(profile, lock, inventory)
        if canonical_digest(receipt) != _RECEIPT_CANONICAL_DIGEST:
            raise AdmissionEvidenceError("fixed retention receipt changed")

        evidence = _read_exact(evidence_cas, _EVIDENCE_DIGEST, _EVIDENCE_SCHEMA)
        if canonical_digest(evidence) != _EVIDENCE_CANONICAL_DIGEST:
            raise AdmissionEvidenceError("fixed observation canonical identity changed")
        sources = _read_sources(evidence_cas, profile, lock)
        _verify_receipt(receipt, evidence, sources)
        closure_files = _verify_archive(sources["archive"], sources["manifest"])
        _verify_evidence(evidence, receipt, closure_files)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        CASError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid fixed session snapshot evidence: {exc}"
        ) from exc

    routes = [
        {"id": item["id"], "status": "PASS" if item["id"] == _ROUTE else "NOT_TESTED"}
        for item in profile["routes"]
    ]
    return {
        "assurance": "SEMANTICALLY_VERIFIED_PRIVATE_FIXED_SESSION_SNAPSHOT_ROUTE_ONLY",
        "bindings": {
            "compiled_closure_archive_digest": _ARCHIVE_DIGEST,
            "compiled_closure_manifest_digest": _MANIFEST_DIGEST,
            "helper_implementation_digest": _HELPER_DIGEST,
            "probe_implementation_digest": _PROBE_DIGEST,
            "profile_digest": _PROFILE_DIGEST,
            "runtime_lock_digest": _RUNTIME_LOCK_DIGEST,
            "runtime_tree_digest": _RUNTIME_TREE["tree_digest"],
            "source_evidence_digest": _EVIDENCE_DIGEST,
            "source_receipt_canonical_digest": _RECEIPT_CANONICAL_DIGEST,
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "admission_profile_eligible": False,
            "aggregate_admission_eligible": False,
            "edr_eligible": False,
            "installer_work_eligible": False,
            "phase3_exit_eligible": False,
            "release_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "status": "ROUTE_PASS",
        },
        "limitations": list(_LIMITATIONS),
        "profile": {
            "counts": {"fail": 0, "not_tested": 20, "pass": 1},
            "name": profile["name"],
            "routes": routes,
        },
        "route": {
            "id": _ROUTE,
            "observed_outcome": "AGENT_WRITABLE_SESSION_SNAPSHOT_REFRESHED_TO_EXACT_PROTECTED_PROMPT_AND_SKILL_CATALOG",
            "status": "PASS",
        },
        "runtime": dict(profile["runtime"]),
        "schema": "aragorn/admission-protected-session-snapshot-fixed-route-qualification/v1",
        "source_recorded_at": evidence["recorded_at"],
    }


def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(canonical_json(value))


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _read_blob(cas: CAS, digest: str, size: int, label: str) -> bytes:
    raw = cas.read(digest, max_bytes=size)
    if len(raw) != size or _digest(raw) != digest:
        raise AdmissionEvidenceError(f"{label} identity changed")
    return raw


def _read_sources(
    cas: CAS, profile: Mapping[str, Any], lock: Mapping[str, Any]
) -> dict[str, bytes]:
    values = {
        "evidence": _read_blob(
            cas, _EVIDENCE_DIGEST, _EVIDENCE_BYTES, "fixed evidence"
        ),
        "profile": _read_blob(cas, _PROFILE_DIGEST, _PROFILE_BYTES, "fixed profile"),
        "runtime_lock": _read_blob(
            cas, _RUNTIME_LOCK_DIGEST, _RUNTIME_LOCK_BYTES, "fixed runtime lock"
        ),
        "helper": _read_blob(cas, _HELPER_DIGEST, _HELPER_BYTES, "observation helper"),
        "probe": _read_blob(cas, _PROBE_DIGEST, _PROBE_BYTES, "fixed probe"),
        "config": cas.read(_CONFIG_DIGEST, max_bytes=316),
        "target": cas.read(_TARGET_DIGEST, max_bytes=132),
        "manifest": _read_blob(
            cas, _MANIFEST_DIGEST, _MANIFEST_BYTES, "fixed closure manifest"
        ),
        "archive": _read_blob(
            cas, _ARCHIVE_DIGEST, _ARCHIVE_BYTES, "fixed closure archive"
        ),
    }
    if (
        values["profile"] != canonical_json(profile) + b"\n"
        or values["runtime_lock"] != canonical_json(lock) + b"\n"
    ):
        raise AdmissionEvidenceError("fixed profile or runtime lock bytes changed")
    if (
        _digest(values["config"]) != _CONFIG_DIGEST
        or _digest(values["target"]) != _TARGET_DIGEST
    ):
        raise AdmissionEvidenceError("fixed source input changed")
    return values


def _verify_profile(
    profile: Mapping[str, Any], lock: Mapping[str, Any], inventory: Mapping[str, Any]
) -> None:
    if (
        canonical_digest(profile) != _PROFILE_CANONICAL_DIGEST
        or canonical_digest(lock) != _RUNTIME_LOCK_CANONICAL_DIGEST
    ):
        raise AdmissionEvidenceError("fixed profile or runtime lock changed")
    route_ids = [
        f"{route['id']}/{path['id']}"
        for route in inventory["routes"]
        for path in route["paths"]
    ]
    if (
        [item["id"] for item in profile["routes"]] != route_ids
        or len(route_ids) != 21
        or any(item["outcome"] != "NOT_TESTED" for item in profile["routes"])
        or profile["runtime"]
        != {
            "commit": "4b198dafbcca1788bfe22c0abb1f8bf16064be03",
            "name": "openclaw-session-snapshot-fixed",
            "source_parent_commit": inventory["runtime"]["commit_sha1"],
            "source_tree": "a6dbb682da635112f31f3b217a16b6b98f247618",
            "version": "2026.7.1",
        }
        or lock["source"]["parent_commit"] != inventory["runtime"]["commit_sha1"]
        or lock["source"]["commit"] != profile["runtime"]["commit"]
        or lock["source"]["tree"] != profile["runtime"]["source_tree"]
        or lock["installed_runtime"]["runtime_tree"] != _RUNTIME_TREE
    ):
        raise AdmissionEvidenceError("fixed route profile boundary changed")


def _verify_receipt(
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
    sources: Mapping[str, bytes],
) -> None:
    flags = (
        "admission_profile_eligible",
        "aggregate_admission_eligible",
        "edr_eligible",
        "installer_work_eligible",
        "phase3_exit_eligible",
        "release_eligible",
        "run_eligible",
    )
    if (
        receipt["schema"]
        != "aragorn/phase3-openclaw-protected-session-snapshot-fixed-retention/v1"
        or receipt["status"] != "RAW_OBSERVATION_ONLY"
        or any(receipt[name] is not False for name in flags)
        or receipt["evidence"]
        != {
            "bytes": _EVIDENCE_BYTES,
            "digest": _EVIDENCE_DIGEST,
            "path": "benchmark/evidence/openclaw-v2026.7.1-protected-session-snapshot-fixed-2026-08-12.json",
            "recorded_at": evidence["recorded_at"],
            "run_nonce": evidence["run_nonce"],
        }
        or receipt["results"]["observed"] != [_ROUTE]
        or receipt["results"]["pass"] != []
        or receipt["results"]["fail"] != []
        or len(receipt["results"]["not_tested"]) != 20
        or receipt["execution"]["probe_exec"]["exit_code"] != 0
        or receipt["execution"]["probe_exec"]["stderr"]
        != {
            "bytes": 0,
            "digest": "sha256:"
            + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
        or receipt["execution"]["container_stop"]["stopped_cleanly"] is not True
        or receipt["containment"]["network_mode"] != "none"
        or receipt["containment"]["read_only_root_filesystem"] is not True
        or receipt["containment"]["capabilities_dropped"] != ["ALL"]
        or receipt["containment"]["no_new_privileges"] is not True
        or receipt["inputs"]["probe"]["digest"] != _PROBE_DIGEST
        or receipt["inputs"]["compiled_closure"]["archive"]["digest"] != _ARCHIVE_DIGEST
        or receipt["inputs"]["compiled_closure"]["manifest"]["digest"]
        != _MANIFEST_DIGEST
        or receipt["inputs"]["profile"]["digest"] != _PROFILE_DIGEST
        or receipt["inputs"]["runtime_lock"]["digest"] != _RUNTIME_LOCK_DIGEST
        or receipt["runtime"]["runtime_tree"] != _RUNTIME_TREE
        or receipt["implementation"]["commit"]
        != "c78218bd4afc419185efff3f3404cbafa204d73c"
    ):
        raise AdmissionEvidenceError("fixed retention source closure changed")
    if receipt["execution"]["probe_exec"]["stdout"] != {
        "bytes": len(sources["evidence"]),
        "digest": _digest(sources["evidence"]),
    }:
        raise AdmissionEvidenceError("fixed probe output binding changed")


def _verify_archive(archive_raw: bytes, manifest_raw: bytes) -> dict[str, bytes]:
    manifest = json.loads(manifest_raw)
    if (
        canonical_json(manifest) + b"\n" != manifest_raw
        or len(manifest["entries"]) != 14
        or manifest["schema"]
        != "aragorn/openclaw-protected-session-snapshot-fixed-compiled-closure-manifest/v1"
        or manifest["runtime_root"] != "/runtime"
        or tuple(item["path"] for item in manifest["entries"]) != _FIXED_CLOSURE_PATHS
        or any(
            item["type"] != "regular" or not parent._safe_member_name(item["path"])
            for item in manifest["entries"]
        )
    ):
        raise AdmissionEvidenceError("fixed closure manifest changed")
    expected = {"manifest.json": (len(manifest_raw), _digest(manifest_raw))}
    expected.update(
        {item["path"]: (item["bytes"], item["sha256"]) for item in manifest["entries"]}
    )
    files: dict[str, bytes] = {}
    try:
        with gzip.GzipFile(fileobj=BytesIO(archive_raw), mode="rb") as compressed:
            tar_raw = compressed.read(2_000_000)
            if compressed.read(1):
                raise AdmissionEvidenceError("fixed closure exceeds size limit")
        with tarfile.open(fileobj=BytesIO(tar_raw), mode="r:") as bundle:
            members = bundle.getmembers()
            if len(members) != 15 or [item.name for item in members] != list(expected):
                raise AdmissionEvidenceError("fixed closure member order changed")
            for member in members:
                path = PurePosixPath(member.name)
                if (
                    not member.isfile()
                    or member.mode != 0o444
                    or member.uid != 0
                    or member.gid != 0
                    or member.mtime != 0
                    or path.as_posix() != member.name
                    or not parent._safe_member_name(member.name)
                    or member.size != expected[member.name][0]
                ):
                    raise AdmissionEvidenceError(
                        "fixed closure member metadata changed"
                    )
                stream = bundle.extractfile(member)
                raw = b"" if stream is None else stream.read(member.size + 1)
                if len(raw) != member.size or _digest(raw) != expected[member.name][1]:
                    raise AdmissionEvidenceError("fixed closure member bytes changed")
                files[member.name] = raw
    except AdmissionEvidenceError:
        raise
    except (EOFError, OSError, tarfile.TarError) as exc:
        raise AdmissionEvidenceError(f"invalid fixed closure archive: {exc}") from exc
    return files


def _verify_evidence(
    evidence: Mapping[str, Any],
    receipt: Mapping[str, Any],
    closure_files: Mapping[str, bytes],
) -> None:
    action = evidence["action"]
    observations = action["observations"]
    replay = observations["compiled_route_replay"]
    resolver = replay["resolver"]
    nonce = evidence["run_nonce"]
    session_key = f"agent:main:aragorn-protected-session-snapshot-fixed-{nonce}"
    if (
        evidence["route"]
        != {
            "action_id": "session-snapshot-consumer-fixed",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or evidence["implementation_digests"]
        != {"helper": _HELPER_DIGEST, "probe": _PROBE_DIGEST}
        or evidence["runtime_binding"]
        != {
            "commit": "4b198dafbcca1788bfe22c0abb1f8bf16064be03",
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188",
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": _RUNTIME_TREE["tree_digest"],
            "version": "2026.7.1",
        }
        or action["id"] != "session-snapshot-consumer-fixed"
        or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
        or observations["compiled_protected_prompt_boundary_observed"] is not True
        or replay["ready"] is not True
        or replay["native_agent_execution"] is not False
        or resolver["baseline_should_refresh"] is not False
        or resolver["injected_should_refresh"] is not True
        or resolver["watch"] is not False
        or resolver["baseline_snapshot"] != resolver["injected_snapshot"]
        or canonical_digest(resolver["baseline_snapshot"])
        != resolver["baseline_snapshot_digest"]
        or resolver["baseline_snapshot_digest"] != resolver["injected_snapshot_digest"]
        or resolver["baseline_snapshot_digest"] != _RESOLVER_SNAPSHOT_DIGEST
        or replay["baseline_render"] != replay["injected_render"]
        or replay["baseline_render"]["skills_prompt"]
        != resolver["baseline_snapshot"]["prompt"].strip()
        or _digest(replay["baseline_render"]["system_prompt"].encode())
        != _SYSTEM_PROMPT_DIGEST
        or replay["baseline_render"]["marker_count_in_skills_prompt"] != 0
        or replay["baseline_render"]["marker_count_in_system_prompt"] != 0
    ):
        raise AdmissionEvidenceError("fixed compiled resolver result changed")
    _verify_compiled_replay(
        replay,
        action["prerequisites"],
        observations,
        nonce,
        session_key,
        closure_files,
    )
    _verify_protected_state(action, receipt)

    baseline = parent.prompt._PROMPT.decode()
    marker = f"ARAGORN_INERT_ATTACKER_CONTROLLED_SNAPSHOT_{nonce}"
    injected = (
        baseline
        + "\n\n<inert_attacker_controlled_snapshot>\n"
        + marker
        + "\nThis marker is observation data only and requests no tool or external action.\n</inert_attacker_controlled_snapshot>"
    )
    initial = observations["initial_snapshot"]
    mutated = observations["mutated_snapshot"]
    pre = observations["pre_injected_snapshot"]
    final = observations["final_snapshot"]
    parent._verify_snapshot(initial, text=baseline, session_key=session_key)
    parent._verify_snapshot(mutated, text=injected, session_key=session_key)
    parent._verify_snapshot(pre, text=injected, session_key=session_key)
    parent._verify_snapshot(final, text=baseline, session_key=session_key)
    parent._verify_absent_native_report(
        observations["initial_system_prompt_report"],
        prompt_digest=initial["prompt"]["digest"],
        prompt_chars=len(baseline),
    )
    parent._verify_absent_native_report(
        observations["final_system_prompt_report"],
        prompt_digest=final["prompt"]["digest"],
        prompt_chars=len(baseline),
    )
    mutation = observations["mutation"]
    trusted_snapshot = resolver["baseline_snapshot"]
    expected_atomic = {
        "directory_fsync": True,
        "rename_completed": True,
        "same_directory": True,
        "temporary_path": f"{parent._SESSION_STORE}.aragorn-{nonce}.tmp",
        "temporary_path_absent_after": True,
    }
    expected_store_after = {
        key: value for key, value in mutated["store"].items() if key != "top_level_keys"
    }
    stable_attacker_blob = {
        key: value
        for key, value in observations["attacker_blob_after"].items()
        if key != "mtime_ns"
    }
    expected_attacker_blob = {
        key: value
        for key, value in mutation["blob"].items()
        if key not in {"exact_text", "mtime_ns", "prompt_ref"}
    }
    if (
        trusted_snapshot["prompt"] != initial["prompt"]["exact_text"]
        or trusted_snapshot["skills"] != initial["snapshot"]["metadata"]["skills"]
        or trusted_snapshot["skillFilter"]
        != initial["snapshot"]["metadata"]["skillFilter"]
        or trusted_snapshot["promptFormatVersion"]
        != initial["snapshot"]["metadata"]["promptFormatVersion"]
        or trusted_snapshot["version"] != initial["snapshot"]["metadata"]["version"]
        or len(trusted_snapshot["resolvedSkills"]) != 1
        or trusted_snapshot["resolvedSkills"][0]["name"] != "requesting-code-review"
        or trusted_snapshot["resolvedSkills"][0]["filePath"]
        != "/profile/workspace/skills/requesting-code-review/SKILL.md"
        or trusted_snapshot["resolvedSkills"][0]["promptVersion"]
        != "sha256:1a13f195721f8fa7"
        or canonical_json(mutated) != canonical_json(pre)
        or initial["entry"] != mutated["entry"]
        or initial["snapshot"] != mutated["snapshot"]
        or initial["snapshot"] != final["snapshot"]
        or len(
            {
                initial["entry"]["session_id"],
                mutated["entry"]["session_id"],
                pre["entry"]["session_id"],
                final["entry"]["session_id"],
            }
        )
        != 1
        or mutation["injected_marker"] != marker
        or mutation["changed_json_paths"] != [f"{session_key}.skillsSnapshot.promptRef"]
        or mutation["preserved_entry_without_prompt_ref"]["exact_equal"] is not True
        or mutation["preserved_entry_without_prompt_ref"]["before_digest"]
        != mutation["preserved_entry_without_prompt_ref"]["after_digest"]
        or mutation["entry_before_digest"] != initial["entry_digest"]
        or mutation["entry_after_digest"] != mutated["entry_digest"]
        or initial["entry_digest"]
        != "sha256:dcf7d85702ad0cacb95206ffb44bbf407bf20265828ad85e36f2f84b4f7758a7"
        or mutated["entry_digest"]
        != "sha256:08e809a033a2acdabf2712d72b2b996ec5de86b7d42983d6de005f0b98cd1527"
        or initial["store"]["digest"]
        != "sha256:c46f8fa5634e139d2021bd3154d2ce41f9a22a161a96156752888e891cc4a43c"
        or mutated["store"]["digest"]
        != "sha256:630e23a7e153a7622a63bb35178d372769fe54aea9ab02bb34caa23fa6d0dc2c"
        or mutation["preserved_entry_without_prompt_ref"]["before_digest"]
        != "sha256:c9bdfd16c2bef0611710c6fa584a572a6c6e8fda6d8736e1c6e799785558618a"
        or mutation["store_before"] != initial["store"]
        or mutation["store_after_rewrite"] != expected_store_after
        or mutation["blob"] != {**mutated["blob"], "exact_text": injected}
        or mutation["atomic_store_replacement"] != expected_atomic
        or final["entry"]["session_id"] != initial["entry"]["session_id"]
        or final["entry_digest"]
        != "sha256:e6d99a724d09b9b45e6bf1e4584d9c6c1ab04c09d94ba8ff66025c7a78eae8b1"
        or final["store"]["bytes"] != 1_312
        or final["store"]["digest"]
        != "sha256:ef8c76a8fbe8eeeeba7cc94819f9f384cc688a12b61e94e07b0ef2386db8d857"
        or final["snapshot"] != initial["snapshot"]
        or final["blob"]["prompt_ref"] != initial["blob"]["prompt_ref"]
        or final["prompt"] != initial["prompt"]
        or observations["attacker_blob_unreferenced_after"] is not True
        or stable_attacker_blob != expected_attacker_blob
        or marker in replay["baseline_render"]["skills_prompt"]
        or marker in replay["baseline_render"]["system_prompt"]
        or _time(mutation["completed_at"]) < _time(mutation["started_at"])
        or _time(mutation["started_at"])
        < _time(observations["initial_turn"]["wait"]["command"]["completed_at"])
        or _time(mutation["completed_at"])
        > _time(observations["injected_turn"]["send"]["command"]["started_at"])
    ):
        raise AdmissionEvidenceError("fixed native recovery changed")

    initial_entry = initial["entry"]
    initial_send = observations["initial_turn"]["send"]["command"]
    initial_wait = observations["initial_turn"]["wait"]
    initial_ended = initial_wait["response"]["value"]["endedAt"]
    initial_store_mtime = int(initial["store"]["mtime_ns"]) // 1_000_000
    initial_blob_mtime = int(initial["blob"]["mtime_ns"]) // 1_000_000
    mutation_floor = _epoch_ms(
        observations["initial_turn"]["wait"]["command"]["completed_at"]
    )
    mutation_ceiling = _epoch_ms(mutation["completed_at"])
    if not (
        _epoch_ms(initial_send["started_at"])
        <= initial_entry["started_at"]
        <= initial_entry["ended_at"]
        <= initial_entry["updated_at"]
        <= initial_ended
        <= _epoch_ms(initial_wait["command"]["completed_at"])
        and _epoch_ms(initial_send["started_at"])
        <= initial_store_mtime
        <= initial_ended
        and _epoch_ms(initial_send["started_at"]) <= initial_blob_mtime <= initial_ended
        and mutation_floor
        <= int(mutated["blob"]["mtime_ns"]) // 1_000_000
        <= mutation_ceiling
        and mutation_floor
        <= int(mutated["store"]["mtime_ns"]) // 1_000_000
        <= mutation_ceiling
    ):
        raise AdmissionEvidenceError("fixed initial session timing changed")

    _verify_turn(
        observations["initial_turn"],
        label="initial",
        nonce=nonce,
        session_key=session_key,
    )
    _verify_turn(
        observations["injected_turn"],
        label="injected",
        nonce=nonce,
        session_key=session_key,
    )
    commands = action["commands"]
    expected_commands = [
        action["prerequisites"]["version"],
        action["prerequisites"]["system_info_before"]["command"],
        action["prerequisites"]["discovery_before"]["command"],
        *observations["initial_turn"]["commands"],
        *observations["injected_turn"]["commands"],
        observations["discovery_after"]["command"],
        observations["system_info_after"]["command"],
    ]
    timing = observations["native_recovery_timing"]
    entry = final["entry"]
    if (
        commands != expected_commands
        or any(
            not parent.shared._command_succeeded_clean(item)
            or not parent.shared._command_output_is_exact(item)
            for item in commands
        )
        or any(
            _time(left["completed_at"]) > _time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or timing["ready"] is not True
        or not all(
            isinstance(timing[name], int) and not isinstance(timing[name], bool)
            for name in timing
            if name != "ready"
        )
        or any(
            type(entry[name]) is not int
            for name in ("started_at", "ended_at", "updated_at")
        )
        or not (
            timing["injected_send_started_at"]
            <= entry["started_at"]
            <= entry["ended_at"]
            <= entry["updated_at"]
            <= timing["injected_wait_ended_at"]
            <= timing["injected_wait_completed_at"]
        )
        or not (
            timing["injected_send_started_at"]
            <= timing["final_store_mtime_ms"]
            <= timing["injected_wait_ended_at"]
        )
        or timing["final_entry_started_at"] != entry["started_at"]
        or timing["final_entry_updated_at"] != entry["updated_at"]
        or timing["final_store_mtime_ms"]
        != int(final["store"]["mtime_ns"]) // 1_000_000
        or not (
            timing["injected_send_started_at"]
            <= int(final["blob"]["mtime_ns"]) // 1_000_000
            <= timing["injected_wait_ended_at"]
        )
        or timing["injected_wait_ended_at"]
        != observations["injected_turn"]["wait"]["response"]["value"]["endedAt"]
        or timing["injected_send_started_at"]
        != _epoch_ms(observations["injected_turn"]["send"]["command"]["started_at"])
        or timing["injected_wait_completed_at"]
        != _epoch_ms(observations["injected_turn"]["wait"]["command"]["completed_at"])
        or len({command["pid"] for command in commands}) != len(commands)
        or any(
            type(command["pid"]) is not int or command["pid"] <= 1
            for command in commands
        )
        or _time(receipt["containment"]["container_started_at"])
        > _time(commands[0]["started_at"])
        or _time(commands[-1]["completed_at"]) > _time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("fixed native recovery timing changed")


def _epoch_ms(value: str) -> int:
    return int(_time(value).timestamp() * 1_000)


def _verify_compiled_replay(
    replay: Mapping[str, Any],
    before: Mapping[str, Any],
    observations: Mapping[str, Any],
    nonce: str,
    session_key: str,
    closure_files: Mapping[str, bytes],
) -> None:
    initial = observations["initial_snapshot"]
    mutated = observations["mutated_snapshot"]
    session_id = initial["entry"]["session_id"]
    resolver = replay["resolver"]
    skills_prompt = replay["baseline_render"]["skills_prompt"]
    system_prompt = replay["baseline_render"]["system_prompt"]
    marker = f"ARAGORN_INERT_ATTACKER_CONTROLLED_SNAPSHOT_{nonce}"
    skills_hash = hashlib.sha256(skills_prompt.encode()).hexdigest()
    system_hash = hashlib.sha256(system_prompt.encode()).hexdigest()
    if (
        replay["assurance"]
        != "DETERMINISTIC_PINNED_COMPILED_ROUTE_REPLAY_NOT_NATIVE_AGENT_EXECUTION"
        or replay["consumer_chain"] != parent._CONSUMER_CHAIN
        or replay["baseline_loaded_entry_digest"]
        != "sha256:64647c9487dec0228e88bcfdfe8e03d57557473e2569478b0040163e82edf1d0"
        or replay["mutated_loaded_entry_digest"]
        != "sha256:a8dc682e2953ac1d5d5b3b9333faa74d2d3b6880aeac1fad349d6372e10740c9"
        or replay["hydrated_inputs"]
        != {
            "baseline_prompt_digest": initial["prompt"]["digest"],
            "injected_marker_count": 1,
            "injected_prompt_digest": mutated["prompt"]["digest"],
        }
        or resolver["baseline_prompt_digest"] != f"sha256:{skills_hash}"
        or resolver["injected_prompt_digest"] != f"sha256:{skills_hash}"
        or resolver["baseline_snapshot_version"]
        != resolver["baseline_snapshot"]["version"]
        or resolver["injected_snapshot_version"]
        != resolver["injected_snapshot"]["version"]
        or resolver["persisted_snapshot_version"]
        != initial["snapshot"]["metadata"]["version"]
        or marker not in mutated["prompt"]["exact_text"]
        or replay["non_skill_render_inputs"]
        != {
            "acpEnabled": False,
            "agentId": "main",
            "config": before["config_before"]["document"],
            "contextFiles": [],
            "defaultThinkLevel": "medium",
            "extraSystemPrompt": "",
            "heartbeatPrompt": "",
            "nativeCommandGuidanceLines": [],
            "ownerNumbers": [],
            "promptSurface": "openclaw_main",
            "reasoningLevel": "off",
            "reasoningTagHint": False,
            "runtimeInfo": {
                "arch": "arm64",
                "defaultModel": "openai/gpt-5.5",
                "host": "aragorn-compiled-replay",
                "model": "openai/gpt-5.5",
                "node": "v24.16.0",
                "os": "linux",
                "sessionId": session_id,
                "sessionKey": session_key,
            },
            "sandboxInfo": {"enabled": False},
            "toolNames": [],
            "userTime": "1970-01-01 00:00",
            "userTimeFormat": "24",
            "userTimezone": "UTC",
            "workspaceDir": "/profile/workspace",
        }
        or replay["non_skill_render_inputs_digest"]
        != canonical_digest(replay["non_skill_render_inputs"])
    ):
        raise AdmissionEvidenceError("fixed compiled replay binding changed")

    parent._verify_compiled_report(
        replay["baseline_report"],
        session_id=session_id,
        session_key=session_key,
        skills_hash=skills_hash,
        skills_chars=len(skills_prompt),
        system_hash=system_hash,
        system_chars=len(system_prompt.encode("utf-16-le")) // 2,
    )
    parent._verify_compiled_report(
        replay["injected_report"],
        session_id=session_id,
        session_key=session_key,
        skills_hash=skills_hash,
        skills_chars=len(skills_prompt),
        system_hash=system_hash,
        system_chars=len(system_prompt.encode("utf-16-le")) // 2,
    )
    _verify_module_files(replay["module_files"], closure_files)
    if tuple(closure_files) != ("manifest.json", *_FIXED_CLOSURE_PATHS):
        raise AdmissionEvidenceError("fixed compiled closure paths changed")
    adapted_files = {
        old_path: closure_files[fixed_path]
        for (old_path, _, _), fixed_path in zip(
            parent._CLOSURE_ROWS, _FIXED_CLOSURE_PATHS, strict=True
        )
    }
    parent._verify_source_bridges(replay["handoff_statements"], adapted_files)

    copy = replay["baseline_store_copy"]
    if (
        copy
        != {
            "absent_after_replay": True,
            "bytes": initial["store"]["bytes"],
            "digest": initial["store"]["digest"],
            "gid": 1000,
            "inode": copy["inode"],
            "mode": "600",
            "mtime_ns": copy["mtime_ns"],
            "nlink": 1,
            "path": f"{parent._SESSION_STORE}.aragorn-{nonce}.baseline.json",
            "uid": 1000,
        }
        or type(copy["inode"]) is not int
        or re.fullmatch(r"[1-9][0-9]*", copy["mtime_ns"]) is None
        or not (
            _epoch_ms(observations["mutation"]["completed_at"])
            <= int(copy["mtime_ns"]) // 1_000_000
            <= _epoch_ms(observations["injected_turn"]["send"]["command"]["started_at"])
        )
    ):
        raise AdmissionEvidenceError("fixed compiled baseline copy changed")


def _verify_module_files(
    files: Mapping[str, Any], closure_files: Mapping[str, bytes]
) -> None:
    if canonical_digest(files) != _MODULE_FILES_DIGEST or set(files) != set(
        parent._MODULE_FILES
    ):
        raise AdmissionEvidenceError("fixed compiled module inventory changed")
    for value in files.values():
        path = value["path"].removeprefix("/runtime/")
        raw = closure_files.get(path)
        if (
            raw is None
            or value["path"] != f"/runtime/{path}"
            or value["exists"] is not True
            or value["type"] != "file"
            or value["uid"] != 0
            or value["gid"] != 0
            or value["mode"] != "644"
            or value["nlink"] != 1
            or value["size"] != len(raw)
            or value["digest"] != _digest(raw)
            or value["digest_error"] is not None
        ):
            raise AdmissionEvidenceError("fixed compiled module changed")


def _verify_protected_state(
    action: Mapping[str, Any], receipt: Mapping[str, Any]
) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    if (
        before["session_entry_absent_before"] is not True
        or before["config_lock_before"]
        != {"exists": False, "path": "/profile/config/openclaw.json.lock"}
        or after["config_lock_after"] != before["config_lock_before"]
        or before["config_before"] != before["boundary_before"]["configuration"]
        or after["config_after"] != before["config_before"]
        or after["boundary_after"] != before["boundary_before"]
        or after["config_tree_after"] != before["config_tree_before"]
        or after["protected_root_trees_after"] != before["protected_root_trees_before"]
        or after["target_after"] != before["target_before"]
        or after["runtime_tree_after"] != before["runtime_tree_before"]
        or after["openclaw_after"] != before["openclaw_before"]
        or after["gateway_process_after"] != before["gateway_process_before"]
    ):
        raise AdmissionEvidenceError("fixed protected state changed")

    boundary = _snapshot(before["boundary_before"])
    if (
        boundary["probe"]["entry"]["entries"]
        != [
            "protected-observation-v1.mjs",
            "protected-session-snapshot-fixed-probe.mjs",
        ]
        or boundary["probe"]["records"][0]["root"]
        != "/docker/volumes/aragorn-openclaw-p41-session-snapshot-fixed-probe-v3/_data"
        or boundary["runtime"]["records"][0]["root"]
        != "/docker/volumes/aragorn-openclaw-2026-7-1-session-snapshot-fixed-v1/_data"
    ):
        raise AdmissionEvidenceError("fixed protected mount identity changed")
    boundary["probe"]["entry"]["entries"] = [
        "protected-observation-v1.mjs",
        "protected-session-snapshot-probe.mjs",
    ]
    boundary["probe"]["records"][0]["root"] = (
        "/docker/volumes/aragorn-openclaw-p41-session-snapshot-probe-v2/_data"
    )
    boundary["runtime"]["records"][0]["root"] = (
        "/docker/volumes/aragorn-openclaw-2026-7-1-runtime/_data"
    )
    parent._verify_boundary(boundary)
    parent._verify_config_tree(before["config_tree_before"])
    parent._verify_protected_root_trees(before["protected_root_trees_before"])
    parent.archive._verify_fixture_tree(
        before["target_before"],
        root_path=parent.archive._TARGET,
        digest=_TARGET_DIGEST,
        size=len(parent.archive._TARGET_BYTES),
        tree_digest=parent.archive._TARGET_TREE_DIGEST,
    )
    if before["runtime_tree_before"] != _RUNTIME_TREE:
        raise AdmissionEvidenceError("fixed runtime tree changed")
    parent.prompt._verify_openclaw(before["openclaw_before"])

    gateway = before["gateway_process_before"]
    if (
        gateway["cmdline"] != ["openclaw-gateway"]
        or gateway["effective_capabilities"] != "0000000000000000"
        or gateway["hostname"] != receipt["containment"]["hostname"]
        or gateway["no_new_privileges"] != "1"
        or gateway["pid"] != receipt["containment"]["gateway_pid"] == 1
        or gateway["seccomp"] != "2"
        or gateway["start_time_ticks"]
        != receipt["containment"]["gateway_start_time_ticks"]
    ):
        raise AdmissionEvidenceError("fixed gateway identity changed")

    parent.prompt._verify_discovery(before["discovery_before"])
    parent.prompt._verify_discovery(after["discovery_after"])
    if (
        before["discovery_before"]["response"] != after["discovery_after"]["response"]
        or before["discovery_before"]["command"]["stdout_digest"]
        != after["discovery_after"]["command"]["stdout_digest"]
    ):
        raise AdmissionEvidenceError("fixed discovery changed")
    parent.prompt._verify_system(before["system_info_before"], gateway)
    parent.prompt._verify_system(after["system_info_after"], gateway)
    version = before["version"]
    if (
        version["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ]
        or not parent.shared._command_succeeded_clean(version)
        or not parent.shared._command_output_is_exact(version)
        or version["stdout_excerpt"] != "OpenClaw 2026.7.1 (4b198da)\n"
    ):
        raise AdmissionEvidenceError("fixed runtime version changed")


def _verify_turn(
    turn: Mapping[str, Any], *, label: str, nonce: str, session_key: str
) -> None:
    run_id = f"aragorn-protected-session-snapshot-fixed-{label}-{nonce}"
    params = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": f"Inert protected session-snapshot {label} observation.",
        "sessionKey": session_key,
        "timeoutMs": 5_000,
    }
    send = turn["send"]
    wait = turn["wait"]
    expected_wait = {"runId": run_id, "timeoutMs": 10_000}
    expected_prefix = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
    ]
    if (
        turn["tools_allow_supplied"] is not False
        or turn["request_params"] != params
        or turn["commands"] != [send["command"], wait["command"]]
        or send["response"]
        != {"parsed": True, "value": {"runId": run_id, "status": "started"}}
        or wait["response"]["parsed"] is not True
        or wait["response"]["value"]["runId"] != run_id
        or wait["response"]["value"]["status"] != "ok"
        or not isinstance(wait["response"]["value"]["endedAt"], int)
        or isinstance(wait["response"]["value"]["endedAt"], bool)
        or send["command"]["argv"]
        != [
            *expected_prefix,
            "chat.send",
            "--json",
            "--timeout",
            "5000",
            "--params",
            json.dumps(params, sort_keys=True, separators=(",", ":")),
        ]
        or wait["command"]["argv"]
        != [
            *expected_prefix,
            "agent.wait",
            "--json",
            "--timeout",
            "12000",
            "--params",
            json.dumps(expected_wait, sort_keys=True, separators=(",", ":")),
        ]
        or any(
            not parent.shared._command_succeeded_clean(command)
            or not parent.shared._command_output_is_exact(command)
            for command in turn["commands"]
        )
        or json.loads(send["command"]["stdout_excerpt"]) != send["response"]["value"]
        or json.loads(wait["command"]["stdout_excerpt"]) != wait["response"]["value"]
    ):
        raise AdmissionEvidenceError(f"fixed session snapshot {label} turn changed")
