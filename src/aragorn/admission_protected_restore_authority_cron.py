"""Compose the exact restore-authority cron-rescan qualification."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_archive as archive
from . import admission_protected_cron as cron
from . import admission_protected_curator_restore as curator
from . import admission_protected_prompt as legacy_prompt
from . import admission_protected_restore_authority_chat as parent_chat
from . import admission_routes
from . import admission_runtime_profile as runtime_profile
from .admission_evidence import AdmissionEvidenceError, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/reload/cron-rescan"
_PARENT_PASS_ROUTES = frozenset(
    {
        "ADM-02/update/archive-source-force-replacement",
        "ADM-02/update/config-entry-activation",
        "ADM-02/update/curator-restore-activation",
        "ADM-02/update/workshop-proposal-apply",
        "ADM-02/reload/chat-session-snapshot-consumer",
        "ADM-02/reload/fresh-session-reset",
        "ADM-02/reload/missing-prompt-blob-rebuild",
        "ADM-02/reload/session-snapshot-consumer",
    }
)
_PASS_ROUTES = _PARENT_PASS_ROUTES | {_ROUTE}
_PARENT_QUALIFICATION_DIGEST = (
    "sha256:d8fbdda435fa6e5476d032c004967b29cc38291f8d23fb3a6d362f3cd0be9d42"
)
_RUNTIME_CANDIDATES_DIGEST = (
    "sha256:948dbed03bef5e48a63b11867132c216e06dcc932d07b7701fa11dd4e6e99ab3"
)
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:71c722ce58ca839e3f981e8471311bf26c6942486bcf10988ad28cc574582257"
)
_RECEIPT_SECTION_DIGESTS = {
    "containment": "sha256:a50534c50666b134a4c3a01a1d4d0bab9955721e052c4798459cad66bb749ce4",
    "evidence": "sha256:12747d9e8cea07d0e27284b2198b797f2a9a0ba50023ba276300f4f69ed4bead",
    "execution": "sha256:3e7c3a60068bd2be0b390d0504a449ed78120b88938c7c2468990b291be11677",
    "implementation": "sha256:46e3cf873542b17b7b324769f7624f7f047ba76c3eafc821bc00126060a099e0",
    "inputs": "sha256:1537ffb6619b72216b37fe2f95e21d0d39cec22394d55c471b1e77a2877c6946",
    "limitations": "sha256:d1bcb15da4271b60966a113973c75344a84e9fc81542b33495a3bbd4536dd65c",
    "results": "sha256:75d308f7d07612a5f528638c849c3400cbdd690f905f04a277c4d54d75af9c5b",
    "runtime": "sha256:f673d0449b86a0994aaa128b0a1020006d47c8f689a3ea4c5437bb49bdd84317",
}
_IMPLEMENTATIONS = {
    "admission_routes": "sha256:550e11465a5e731911be5e752c92a264cf21d6eaded69147355c913254417f56",
    "archive": "sha256:638a06723ea7f500f159f6e784034c755b08e921a3a25ba6ec3e3bf7ce38527f",
    "cron": "sha256:e0cbfb701345e834bfcaa8a29e34660d90dd9a5cd1a7b45de35c6ee330465e65",
    "curator": "sha256:3ba088ca0f097eb843ecd9d6c54ebc3676bf6fb8961db1a28a6066f9584f1a2a",
    "legacy_prompt": "sha256:99e50bd0b18723a0bb37ca8afea04ef8b40c6fd3e159c6e17f26320f4f7c586c",
    "parent_chat": "sha256:ba08cb3707b5648688a01c5e538867afde454edbe585cb0ca1695a9e03eb27f6",
    "runtime_profile": "sha256:adf90754909150fba60b99b1b890e0815c2b5d081ea32dd5b5a698b1f0dfb50b",
}
_EVIDENCE = {
    "bytes": 66_277,
    "canonical_bytes": 66_276,
    "canonical_digest": (
        "sha256:2ec7988b1dd640dede7e50b0001ec3e2a5072ec68802b749354b66c047c59339"
    ),
    "digest": (
        "sha256:0f1ff620c02a35b4396299e3a0fcc50db1c7dae29960621f7b9cbb1359163b41"
    ),
    "path": (
        "benchmark/evidence/openclaw-v2026.7.1-protected-restore-authority-"
        "cron-rescan-2026-08-13.json"
    ),
    "schema": "aragorn/openclaw-protected-cron-rescan-observation/v1",
}
_SOURCES = {
    "profile": (
        "sha256:12e2fb6298d0d968a10aeb2c8e9f902cc6d3146d4bb51054ae194556c7acfb8d",
        3_932,
    ),
    "runtime_lock": (
        "sha256:6021e62e5dfd93fea9cc87f52ca65bdd964472916a99c9f58a913e94a635dd49",
        4_596,
    ),
    "configuration": (
        "sha256:701da2485f2844603c13b40c56876984de5ff9cdc22927f1a5bcd218ba369751",
        359,
    ),
    "source_helper": (
        "sha256:44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b",
        13_609,
    ),
    "helper": (
        "sha256:81db497cbde9c07e211a406699896da37c137358d0b7534d8580eab43c47c216",
        13_609,
    ),
    "source_probe": (
        "sha256:db9c038d41735f9dfb16973e293a007abfadd35340b6425dbd7a95a6ea08c27c",
        26_778,
    ),
    "probe": (
        "sha256:5ddecb878780ca7dc8c939921329964e678140f0bc67aacab52a7b9e184111e4",
        26_777,
    ),
    "target": (
        "sha256:1a13f195721f8fa75974bd4918a25b30e8406ff6d423cd0e3306c391b8fee07a",
        132,
    ),
}
_MATERIALIZER = (
    "sha256:e2d43f37cbe99555cc46a186fb5063ae634df1d9463d592bfc95ef551f01a4ae",
    20_962,
)
_CONFIG_CANONICAL_DIGEST = (
    "sha256:417fc06b87a539654433451aff12509ca7dca28003c9f2cedc91bcc611eba16e"
)
_ACTION_DIGEST = (
    "sha256:10d142bbc134333b295af389a8ea239c6c82eb7e47b7087d5b4933e9bd080f4f"
)
_STATIC_DIGESTS = {
    "boundary": "sha256:27e1e126ffb12055bb7cb4939d6620f3a34195d7b6adc54c1480428f04f2c6c1",
    "config_tree": "sha256:ea1dc2e9c0e26694aa733e4fee1480da5674483745131f661a403c6e3cb7b4c6",
    "modules": "sha256:eafafd410974a982936860a40cc5e796472fa7a567d3bb44eb4baf94b2aca121",
    "openclaw": "sha256:78f80d3bd7845838b5fc0ce709e1910dfdb638887ba300e4fbd67b36b07828e7",
    "protected_roots": "sha256:8cbfb43c7d25141e17bd4467f4e656b21c8c523f85bcebc153b0c9796cb474b9",
    "runtime_tree": "sha256:763e0ef9a251e43c7b7f0af151a58331ca6feb3af5fbb207261e88718bc79eb9",
    "target": "sha256:628c0ba3c90fa35d81f9001e0d69e96a7c36c53f0ecc283d0901f6ab6d0fb02a",
}
_RUNTIME_TREE_DIGEST = (
    "sha256:6448edb21fd2a27dd3cf2b740e0d0dfc3a395e2ccae446853867a95485d54e74"
)
_RECORDED_AT = "2026-08-13T12:08:12.139Z"
_NODE = "/usr/local/bin/node"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_CONFIG = "/profile/config/openclaw.json"
_SESSION_STORE = "/profile/state/agents/main/sessions/sessions.json"
_LIMITATIONS = [
    "NINE_EXACT_PRIVATE_PATCHED_RUNTIME_ROUTE_PASSES_ONLY",
    "SEPARATE_CAPTURE_COMPOSITION_ONLY",
    "CHAT_ROUTE_REUSES_SHARED_PROMPT_REBUILD_CAPTURE_NOT_INDEPENDENT_EXECUTION",
    "BLACK_BOX_NATIVE_CHAT_PERSISTENCE_WITHOUT_DIRECT_SESSION_UPDATES_TRACE",
    "ONE_MISSING_PROMPT_BLOB_TRIGGER_NOT_GENERAL_CHAT_ROUTE_COVERAGE",
    "ONE_EXACT_PRIVATE_PATCHED_RUNTIME_CRON_RESCAN_CAPTURE_ONLY",
    "ONE_FRESH_CAPTURE_NO_REPEATABILITY_CLAIM",
    "ISOLATED_CRON_JOB_CREATED_FORCED_ONCE_AND_REMOVED",
    "BASE_SESSION_ABSENT_BEFORE_FORCED_RUN_SO_NO_EXISTING_SNAPSHOT_REUSE_OR_TAMPER_REPAIR_CLAIM",
    "EXACT_PROTECTED_PROMPTREF_SNAPSHOT_OBSERVED_AFTER_FORCED_CRON_RUN",
    "RUN_ID_EPOCH_AND_RUN_AT_MS_ARE_SEPARATE_CLOCK_READS_CAUSALLY_BOUNDED_NOT_EQUAL",
    "TERMINAL_MODEL_NOT_FOUND_AFTER_SNAPSHOT_CONSTRUCTION_IS_EXPECTED",
    "NO_SUCCESSFUL_MODEL_REPLY_OR_DELIVERY_CLAIM",
    "NO_PROVIDER_NETWORK_OR_PROVIDER_REQUEST_MODEL_SUCCESS_OBSERVED",
    "SESSION_STORE_AND_PROMPT_BLOB_MUTATION_CONFINED_TO_EPHEMERAL_STATE_TMPFS",
    "BLACK_BOX_NATIVE_CRON_PERSISTENCE_WITHOUT_DIRECT_MODULE_EXECUTION_TRACE",
    "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "SOURCE_TO_BINARY_REPRODUCIBILITY_NOT_INDEPENDENTLY_ATTESTED",
    "TWELVE_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "RUN_01_RUN_02_PHASE3_EDR_AND_RELEASE_NOT_ESTABLISHED",
]


def verify_openclaw_protected_restore_authority_cron_rescan(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    runtime_lock: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    chat_qualification: Mapping[str, Any],
) -> dict[str, Any]:
    """Add only the exact isolated cron-rescan PASS to eight routes."""

    try:
        receipt = _snapshot(source_receipt)
        profile = _snapshot(route_profile)
        lock = _snapshot(runtime_lock)
        inventory = _snapshot(route_inventory)
        candidates = _snapshot(runtime_candidates)
        parent = _snapshot(chat_qualification)

        modules = {
            "admission_routes": admission_routes,
            "archive": archive,
            "cron": cron,
            "curator": curator,
            "legacy_prompt": legacy_prompt,
            "parent_chat": parent_chat,
            "runtime_profile": runtime_profile,
        }
        if any(
            _digest(Path(module.__file__).read_bytes()) != _IMPLEMENTATIONS[name]
            for name, module in modules.items()
        ):
            raise AdmissionEvidenceError("cron dependency implementation changed")

        if canonical_digest(receipt) != _RECEIPT_CANONICAL_DIGEST:
            raise AdmissionEvidenceError("cron retention receipt envelope changed")
        if canonical_digest(parent) != _PARENT_QUALIFICATION_DIGEST:
            raise AdmissionEvidenceError("chat parent qualification envelope changed")
        if canonical_digest(candidates) != _RUNTIME_CANDIDATES_DIGEST:
            raise AdmissionEvidenceError("runtime candidates changed")

        admission_routes.validate_openclaw_2026_7_1_route_inventory(
            inventory, candidates
        )
        curator._verify_profile(profile, lock, inventory)
        sources = _read_sources(evidence_cas, profile, lock)
        evidence = _read_evidence(evidence_cas)
        _verify_parent(parent, profile)
        _verify_receipt(receipt, evidence, profile, lock, sources)
        _verify_evidence(evidence, receipt, profile, lock, sources["configuration"])
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
            f"invalid restore-authority cron evidence: {exc}"
        ) from exc

    result = copy.deepcopy(parent)
    for route in result["profile"]["routes"]:
        if route["id"] == _ROUTE:
            route["status"] = "PASS"
            break
    else:  # pragma: no cover - exact parent validation reaches this first
        raise AdmissionEvidenceError("cron route missing")
    result.update(
        {
            "assurance": "SEMANTICALLY_VERIFIED_PRIVATE_RESTORE_AUTHORITY_NINE_ROUTE_COVERAGE_ONLY",
            "bindings": {
                "chat_qualification_canonical_digest": _PARENT_QUALIFICATION_DIGEST,
                "configuration_digest": _SOURCES["configuration"][0],
                "cron_evidence_canonical_digest": _EVIDENCE["canonical_digest"],
                "cron_evidence_digest": _EVIDENCE["digest"],
                "cron_receipt_canonical_digest": _RECEIPT_CANONICAL_DIGEST,
                "legacy_cron_verifier_implementation_digest": _IMPLEMENTATIONS["cron"],
                "materialized_helper_digest": _SOURCES["helper"][0],
                "materialized_probe_digest": _SOURCES["probe"][0],
                "materializer_digest": _MATERIALIZER[0],
                "profile_digest": _SOURCES["profile"][0],
                "runtime_lock_digest": _SOURCES["runtime_lock"][0],
                "runtime_tree_digest": _RUNTIME_TREE_DIGEST,
                "source_helper_digest": _SOURCES["source_helper"][0],
                "source_probe_digest": _SOURCES["source_probe"][0],
                "target_digest": _SOURCES["target"][0],
                "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
            },
            "limitations": list(_LIMITATIONS),
            "schema": "aragorn/admission-protected-restore-authority-cron-route-coverage/v1",
            "source_recorded_at": max(
                parent["source_recorded_at"], evidence["recorded_at"]
            ),
        }
    )
    result["profile"]["counts"] = {"fail": 0, "not_tested": 12, "pass": 9}
    return result


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
        name: _read_blob(cas, digest, size, name)
        for name, (digest, size) in _SOURCES.items()
    }
    if (
        values["profile"] != canonical_json(profile) + b"\n"
        or values["runtime_lock"] != canonical_json(lock) + b"\n"
        or values["target"] != archive._TARGET_BYTES
    ):
        raise AdmissionEvidenceError("cron retained source bytes changed")
    configuration = runtime_profile.load_runtime_profile(values["configuration"])
    if (
        canonical_json(configuration) + b"\n" != values["configuration"]
        or canonical_digest(configuration) != _CONFIG_CANONICAL_DIGEST
        or configuration["skills"]["workshop"]["restoreAuthority"] != "external"
    ):
        raise AdmissionEvidenceError("cron restore-authority config changed")
    return values


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdmissionEvidenceError(f"duplicate cron capture key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AdmissionEvidenceError(f"invalid cron capture constant: {value}")


def _read_evidence(cas: CAS) -> dict[str, Any]:
    raw = _read_blob(cas, _EVIDENCE["digest"], _EVIDENCE["bytes"], "evidence")
    try:
        document = json.loads(
            raw.decode(),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(f"invalid cron capture JSON: {exc}") from exc
    canonical = canonical_json(document)
    if (
        not isinstance(document, dict)
        or canonical_digest(document) != _EVIDENCE["canonical_digest"]
        or len(canonical) != _EVIDENCE["canonical_bytes"]
        or canonical + b"\n" != raw
    ):
        raise AdmissionEvidenceError("cron capture parsed identity changed")
    return document


def _verify_parent(parent: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
    expected_routes = [
        {
            "id": item["id"],
            "status": "PASS" if item["id"] in _PARENT_PASS_ROUTES else "NOT_TESTED",
        }
        for item in profile["routes"]
    ]
    if (
        canonical_digest(parent) != _PARENT_QUALIFICATION_DIGEST
        or parent["schema"]
        != "aragorn/admission-protected-restore-authority-chat-route-coverage/v1"
        or parent["runtime"] != profile["runtime"]
        or parent["profile"]
        != {
            "counts": {"fail": 0, "not_tested": 13, "pass": 8},
            "name": profile["name"],
            "routes": expected_routes,
        }
        or parent["bindings"]["verifier_implementation_digest"]
        != _IMPLEMENTATIONS["parent_chat"]
        or any(
            value is not False
            for key, value in parent["decision"].items()
            if key != "status"
        )
        or parent["decision"]["status"] != "PARTIAL_ROUTE_COVERAGE"
    ):
        raise AdmissionEvidenceError("eight-route chat parent changed")


def _verify_receipt(
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
    profile: Mapping[str, Any],
    lock: Mapping[str, Any],
    sources: Mapping[str, bytes],
) -> None:
    if canonical_digest(receipt) != _RECEIPT_CANONICAL_DIGEST:
        raise AdmissionEvidenceError("cron retention receipt envelope changed")
    if any(
        canonical_digest(receipt[name]) != digest
        for name, digest in _RECEIPT_SECTION_DIGESTS.items()
    ):
        raise AdmissionEvidenceError("cron retention receipt section changed")

    false_fields = (
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
    not_tested = [item["id"] for item in profile["routes"] if item["id"] != _ROUTE]
    inputs = receipt["inputs"]
    implementation = receipt["implementation"]
    runtime = receipt["runtime"]
    if (
        receipt["schema"]
        != "aragorn/phase3-openclaw-protected-restore-authority-cron-rescan-retention/v1"
        or receipt["assurance"]
        != "OPERATOR_RETAINED_PRIVATE_RESTORE_AUTHORITY_RAW_CRON_RESCAN_OBSERVATION_NOT_CONFORMANCE_AUTHORITY"
        or receipt["status"] != "OBSERVED"
        or any(receipt[name] is not False for name in false_fields)
        or receipt["observed_at"] != evidence["recorded_at"]
        or receipt["results"]
        != {
            "fail": [],
            "fail_count": 0,
            "not_tested": not_tested,
            "not_tested_count": 20,
            "observed": [_ROUTE],
            "observed_count": 1,
            "pass": [],
            "pass_count": 0,
        }
        or receipt["evidence"]
        != {
            "bytes": _EVIDENCE["bytes"],
            "canonical_bytes": _EVIDENCE["canonical_bytes"],
            "canonical_digest": _EVIDENCE["canonical_digest"],
            "canonical_lf": True,
            "path": _EVIDENCE["path"],
            "raw_sha256": _EVIDENCE["digest"].removeprefix("sha256:"),
            "recorded_at": evidence["recorded_at"],
            "run_nonce": evidence["run_nonce"],
            "schema": _EVIDENCE["schema"],
        }
        or implementation["harness_commit"]
        != "55b13c153140292a492ee61b3fa129e1d1165129"
        or implementation["harness_parent_commit"]
        != "4c9c8b76d7e610e1701e8ca983bfed1ab2e30bc9"
        or implementation["harness_tree"] != "b2d97e10f38209e3e7ec9959d9a0c1996e079a2a"
        or implementation["harness_commit_signature"]["status"]
        != "GOOD_LOCAL_VERIFICATION"
        or implementation["materializer"]["digest"] != _MATERIALIZER[0]
        or implementation["materializer"]["bytes"] != _MATERIALIZER[1]
        or runtime["commit"] != profile["runtime"]["commit"]
        or runtime["openclaw_digest"] != lock["installed_runtime"]["openclaw_digest"]
        or runtime["runtime_tree"]["tree_digest"] != _RUNTIME_TREE_DIGEST
        or runtime["runtime_tree"]["rehashed_before_and_after"] is not True
        or runtime["module_files_rehashed_before_and_after"] is not True
    ):
        raise AdmissionEvidenceError("cron retention receipt identity changed")

    expected_source_files = {
        item["role"]: (item["digest"], item["bytes"])
        for item in implementation["source_files"]
    }
    generated = {
        item["role"]: (item["digest"], item["bytes"])
        for item in inputs["generated_probe_volume"]["files"]
    }
    if (
        expected_source_files
        != {
            "helper": (_SOURCES["source_helper"][0], len(sources["source_helper"])),
            "probe": (_SOURCES["source_probe"][0], len(sources["source_probe"])),
        }
        or generated
        != {
            "helper": (_SOURCES["helper"][0], len(sources["helper"])),
            "probe": (_SOURCES["probe"][0], len(sources["probe"])),
        }
        or inputs["generated_probe_volume"]["exact_file_count"] != 2
        or inputs["generated_probe_volume"]["retained"] is not True
        or inputs["profile"]["digest"] != _SOURCES["profile"][0]
        or inputs["profile"]["bytes"] != len(sources["profile"])
        or inputs["runtime_lock"]["digest"] != _SOURCES["runtime_lock"][0]
        or inputs["runtime_lock"]["bytes"] != len(sources["runtime_lock"])
        or inputs["configuration"]["digest"] != _SOURCES["configuration"][0]
        or inputs["configuration"]["bytes"] != len(sources["configuration"])
        or inputs["protected_target"]["digest"] != _SOURCES["target"][0]
        or inputs["protected_target"]["bytes"] != len(sources["target"])
    ):
        raise AdmissionEvidenceError("cron retention input closure changed")
    _verify_containment(receipt, evidence)
    _verify_receipt_execution(receipt, evidence)


def _verify_containment(
    receipt: Mapping[str, Any], evidence: Mapping[str, Any]
) -> None:
    containment = receipt["containment"]
    container = containment["container"]
    controls = containment["controls"]
    mounts = {item["destination"]: item for item in containment["mounts"]}
    if (
        containment["command"]
        != [
            _OPENCLAW,
            "gateway",
            "run",
            "--allow-unconfigured",
            "--auth",
            "token",
            "--bind",
            "loopback",
            "--port",
            "18789",
            "--tailscale",
            "off",
            "--ws-log",
            "full",
        ]
        or set(mounts)
        != {
            "/probe",
            "/profile/config",
            "/profile/home/.agents/skills",
            "/profile/state/extensions",
            "/profile/state/plugin-skills",
            "/profile/state/skills",
            "/profile/workspace/.agents/skills",
            "/profile/workspace/skills",
            "/runtime",
        }
        or any(item["read_only"] is not True for item in mounts.values())
        or mounts["/probe"]["volume"]
        != "aragorn-openclaw-restore-authority-cron-probe-55b13c1-d68e79b5"
        or mounts["/runtime"]["volume"]
        != "aragorn-openclaw-2026-7-1-session-snapshot-restore-authority-v1"
        or controls["cap_add"] != []
        or controls["cap_drop"] != ["ALL"]
        or controls["network"] != "none"
        or controls["no_new_privileges"] is not True
        or controls["privileged"] is not False
        or controls["read_only_rootfs"] is not True
        or controls["runtime_user"] != "1000:1000"
        or controls["group_add"] != [982]
        or controls["pids_limit"] != 128
        or controls["restart_policy"] != "no"
        or container["id"]
        != "52bd76dae9fab90732c2f7e4886a6f9834eaefed56e7845362aab993d64d22a1"
        or container["state"]
        != {
            "dead": False,
            "exit_code": 0,
            "oom_killed": False,
            "restart_count": 0,
            "restarting": False,
            "status": "exited",
        }
        or container["retained_stopped"] is not True
        or _time(container["started_at"])
        > _time(evidence["action"]["commands"][0]["started_at"])
        or _time(evidence["recorded_at"]) > _time(container["finished_at"])
    ):
        raise AdmissionEvidenceError("cron containment changed")


def _verify_receipt_execution(
    receipt: Mapping[str, Any], evidence: Mapping[str, Any]
) -> None:
    action = evidence["action"]
    commands = action["commands"]
    execution = receipt["execution"]
    summary = execution["action"]
    projection_keys = (
        "argv",
        "completed_at",
        "error",
        "exit_code",
        "pid",
        "signal",
        "started_at",
        "stderr_bytes",
        "stderr_digest",
        "stdout_bytes",
        "stdout_digest",
    )
    projections = [
        {key: command[key] for key in projection_keys} for command in commands
    ]
    after = action["observations"]
    terminal = after["terminal_result"]
    snapshot = after["snapshot"]
    run_id = terminal["runId"]
    run_match = cron._RUN_ID.fullmatch(run_id)
    if run_match is None:
        raise AdmissionEvidenceError("cron receipt run id changed")
    causal = execution["causal_chain"]
    expected_causal_values = {
        "after_observation_started_at_ms": _epoch_ms(
            after["discovery_after"]["command"]["started_at"]
        ),
        "cleanup_completed_at_ms": _epoch_ms(
            after["cleanup"]["command"]["completed_at"]
        ),
        "cleanup_started_at_ms": _epoch_ms(after["cleanup"]["command"]["started_at"]),
        "diagnostic_at_ms": terminal["diagnostics"]["entries"][0]["ts"],
        "force_completed_at_ms": _epoch_ms(
            after["run"]["request"]["command"]["completed_at"]
        ),
        "force_started_at_ms": _epoch_ms(
            after["run"]["request"]["command"]["started_at"]
        ),
        "poll_completed_at_ms": _epoch_ms(
            after["run"]["terminal_poll"]["command"]["completed_at"]
        ),
        "run_at_delta_ms": terminal["runAtMs"] - int(run_match.group(2)),
        "run_at_ms": terminal["runAtMs"],
        "run_id": run_id,
        "run_id_epoch_ms": int(run_match.group(2)),
        "snapshot_updated_at_ms": snapshot["entry"]["updated_at"],
        "terminal_at_ms": terminal["ts"],
    }
    if (
        summary["status"] != action["status"]
        or summary["reason_codes"] != action["reason_codes"]
        or summary["execution_error"] != action["execution_error"]
        or summary["command_count"] != 9
        or len(commands) != 9
        or summary["command_pids"] != [command["pid"] for command in commands]
        or summary["command_projections"] != projections
        or summary["poll_count"] != after["run"]["poll_count"]
        or summary["command_window"]
        != {
            "completed_at": commands[-1]["completed_at"],
            "started_at": commands[0]["started_at"],
        }
        or any(causal[key] != value for key, value in expected_causal_values.items())
        or causal["all_checks"] is not True
        or execution["container_stop"]["stopped_cleanly"] is not True
        or execution["outer_capture"]["exit_code"] != 0
        or execution["outer_capture"]["stderr_bytes"] != 0
    ):
        raise AdmissionEvidenceError("cron receipt execution join changed")


def _verify_evidence(
    evidence: Mapping[str, Any],
    receipt: Mapping[str, Any],
    profile: Mapping[str, Any],
    lock: Mapping[str, Any],
    config_raw: bytes,
) -> None:
    if canonical_digest(evidence) != _EVIDENCE["canonical_digest"]:
        raise AdmissionEvidenceError("cron observation envelope changed")
    if (
        set(evidence)
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
        or evidence["schema"] != _EVIDENCE["schema"]
        or evidence["recorded_at"] != _RECORDED_AT
        or evidence["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or evidence["implementation_digests"]
        != {"helper": _SOURCES["helper"][0], "probe": _SOURCES["probe"][0]}
        or evidence["route"]
        != {
            "action_id": "cron-rescan",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or re.fullmatch(r"[0-9a-f]{32}", evidence["run_nonce"]) is None
        or evidence["runtime_binding"]
        != {
            "commit": profile["runtime"]["commit"],
            "node_path": _NODE,
            "openclaw_digest": lock["installed_runtime"]["openclaw_digest"],
            "openclaw_path": _OPENCLAW,
            "runtime_tree_digest": _RUNTIME_TREE_DIGEST,
            "version": profile["runtime"]["version"],
        }
    ):
        raise AdmissionEvidenceError("cron observation identity changed")
    _verify_action(evidence["action"], receipt, lock, config_raw)


def _verify_action(
    action: Mapping[str, Any],
    receipt: Mapping[str, Any],
    lock: Mapping[str, Any],
    config_raw: bytes,
) -> None:
    if (
        canonical_digest(action) != _ACTION_DIGEST
        or set(action)
        != {
            "commands",
            "execution_error",
            "id",
            "observations",
            "prerequisites",
            "reason_codes",
            "status",
        }
        or action["id"] != "cron-rescan"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
    ):
        raise AdmissionEvidenceError("cron action identity changed")

    before = action["prerequisites"]
    after = action["observations"]
    stable = (
        (before["boundary_before"], after["boundary_after"], "boundary"),
        (before["config_before"], after["config_after"], None),
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
        (before["gateway_process_before"], after["gateway_process_after"], None),
        (before["module_files_before"], after["module_files_after"], "modules"),
    )
    if any(left != right for left, right, _name in stable) or any(
        name is not None and canonical_digest(left) != _STATIC_DIGESTS[name]
        for left, _right, name in stable
    ):
        raise AdmissionEvidenceError("cron protected state changed")

    configuration = runtime_profile.load_runtime_profile(config_raw)
    boundary = before["boundary_before"]
    gateway = before["gateway_process_before"]
    if (
        boundary["ready"] is not True
        or before["config_before"] != boundary["configuration"]
        or boundary["effective_identity"]
        != {"gid": 1000, "groups": [982, 1000], "uid": 1000}
        or boundary["configuration"]["document"] != configuration
        or boundary["configuration"]["canonical_digest"] != _CONFIG_CANONICAL_DIGEST
        or before["config_lock_before"] != {"exists": False, "path": f"{_CONFIG}.lock"}
        or before["runtime_tree_before"] != lock["installed_runtime"]["runtime_tree"]
        or before["openclaw_before"]["digest"]
        != lock["installed_runtime"]["openclaw_digest"]
        or gateway["cmdline"] != ["openclaw-gateway"]
        or gateway["effective_capabilities"] != "0000000000000000"
        or gateway["hostname"] != receipt["containment"]["container"]["id"][:12]
        or gateway["no_new_privileges"] != "1"
        or gateway["pid"] != 1
        or gateway["seccomp"] != "2"
        or gateway["start_time_ticks"] != "4495291"
    ):
        raise AdmissionEvidenceError("cron protected boundary identity changed")

    legacy_prompt._verify_discovery(before["discovery_before"])
    legacy_prompt._verify_discovery(after["discovery_after"])
    legacy_prompt._verify_system(before["system_info_before"], gateway)
    legacy_prompt._verify_system(after["system_info_after"], gateway)
    if (
        before["discovery_before"]["response"] != after["discovery_after"]["response"]
        or before["system_info_before"]["response"]["value"]["pid"] != gateway["pid"]
    ):
        raise AdmissionEvidenceError("cron native identity changed")
    _verify_version(before["version"])

    job = after["job"]
    job_id = cron._verify_job(job)
    cron._verify_pre_run_state(
        after["session_state_before_forced_run"],
        job_id=job_id,
        session_store_before=before["session_store_before"],
    )
    run = after["run"]
    request = run["request"]
    cron._verify_native_call(
        request, method="cron.run", params={"id": job_id, "mode": "force"}
    )
    pre_run = after["session_state_before_forced_run"]
    run_id = request["response"]["value"].get("runId")
    if (
        request["response"]["value"] != {"enqueued": True, "ok": True, "runId": run_id}
        or not isinstance(run_id, str)
        or cron._RUN_ID.fullmatch(run_id) is None
        or run["poll_count"] != 1
        or len(run["polls"]) != 1
        or run["terminal_poll"] != run["polls"][0]
        or not _time(job["command"]["completed_at"])
        <= _time(pre_run["started_at"])
        <= _time(pre_run["completed_at"])
        <= _time(request["command"]["started_at"])
    ):
        raise AdmissionEvidenceError("cron forced run changed")

    poll = run["terminal_poll"]
    cron._verify_native_call(
        poll, method="cron.runs", params={"id": job_id, "limit": 10}
    )
    terminal = after["terminal_result"]
    if poll["response"]["value"] != {
        "entries": [terminal],
        "hasMore": False,
        "limit": 10,
        "nextOffset": None,
        "offset": 0,
        "total": 1,
    }:
        raise AdmissionEvidenceError("cron terminal history changed")
    cron._verify_snapshot(after["snapshot"], job_id=job_id)
    _verify_terminal(
        terminal,
        job=job,
        run_id=run_id,
        job_id=job_id,
        snapshot=after["snapshot"],
        terminal_poll=poll,
        force_command=request["command"],
    )
    _verify_store(after["session_store_after"], after["snapshot"]["store"])
    cron._verify_native_call(
        after["cleanup"], method="cron.remove", params={"id": job_id}
    )
    if after["cleanup"]["response"]["value"] != {"ok": True, "removed": True}:
        raise AdmissionEvidenceError("cron cleanup changed")
    _verify_commands(action)


def _verify_version(command: Mapping[str, Any]) -> None:
    if (
        command["argv"] != [_NODE, _OPENCLAW, "--version"]
        or command["stdout_excerpt"] != "OpenClaw 2026.7.1 (805a4b1)\n"
        or not runtime_profile._command_succeeded_clean(command)
        or not runtime_profile._command_output_is_exact(command)
    ):
        raise AdmissionEvidenceError("cron version changed")


def _verify_terminal(
    result: Mapping[str, Any],
    *,
    job: Mapping[str, Any],
    run_id: str,
    job_id: str,
    snapshot: Mapping[str, Any],
    terminal_poll: Mapping[str, Any],
    force_command: Mapping[str, Any],
) -> None:
    diagnostic = result["diagnostics"]["entries"][0]
    run_match = cron._RUN_ID.fullmatch(run_id)
    run_epoch = int(run_match.group(2)) if run_match is not None else -1
    run_at = result["runAtMs"]
    snapshot_updated = snapshot["entry"]["updated_at"]
    store_mtime = int(snapshot["store"]["mtime_ns"]) // 1_000_000
    blob_mtime = int(snapshot["blob"]["mtime_ns"]) // 1_000_000
    session_id = result["sessionId"]
    if (
        run_match is None
        or run_match.group(1) != job_id
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
        or diagnostic["message"] != "Unknown model: openai/gpt-5.5"
        or diagnostic["severity"] != "error"
        or diagnostic["source"] != "agent-run"
        or result["nextRunAtMs"] != job["response"]["value"]["nextRunAtMs"]
        or not isinstance(result["durationMs"], int)
        or result["durationMs"] < 0
        or not _epoch_ms(force_command["started_at"])
        <= run_epoch
        <= run_at
        <= _epoch_ms(force_command["completed_at"])
        <= snapshot_updated
        <= store_mtime
        <= blob_mtime
        <= diagnostic["ts"]
        <= result["ts"]
        <= _epoch_ms(terminal_poll["command"]["completed_at"])
    ):
        raise AdmissionEvidenceError("cron terminal causality changed")


def _verify_store(store_after: Mapping[str, Any], store: Mapping[str, Any]) -> None:
    if (
        store_after["path"] != _SESSION_STORE
        or store_after["exists"] is not True
        or store_after["type"] != "file"
        or store_after["uid"] != 1000
        or store_after["gid"] != 1000
        or store_after["mode"] != "600"
        or store_after["nlink"] != 1
        or store_after["size"] != store["bytes"]
        or store_after["digest"] != store["digest"]
        or store_after["inode"] != store["inode"]
        or store_after["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("cron retained session store changed")


def _verify_commands(action: Mapping[str, Any]) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    commands = action["commands"]
    expected = [
        before["version"],
        before["system_info_before"]["command"],
        before["discovery_before"]["command"],
        after["job"]["command"],
        after["run"]["request"]["command"],
        after["run"]["terminal_poll"]["command"],
        after["cleanup"]["command"],
        after["discovery_after"]["command"],
        after["system_info_after"]["command"],
    ]
    if (
        commands != expected
        or len(commands) != 9
        or [command["pid"] for command in commands]
        != [33, 40, 52, 64, 76, 88, 100, 112, 124]
        or len({command["pid"] for command in commands}) != 9
        or any(
            _time(left["completed_at"]) > _time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or _time(commands[-1]["completed_at"]) > _time(_RECORDED_AT)
        or any(
            not runtime_profile._command_succeeded_clean(command)
            or not runtime_profile._command_output_is_exact(command)
            for command in commands
        )
    ):
        raise AdmissionEvidenceError("cron command causality changed")


def _epoch_ms(value: str) -> int:
    return int(_time(value).timestamp() * 1_000)
