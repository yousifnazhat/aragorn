"""Exact-profile qualification for protected OpenClaw cron rescans."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_archive as archive
from . import admission_protected_prompt as prompt
from . import admission_runtime_profile as shared
from .admission_evidence import AdmissionEvidenceError, _read_exact, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_PROFILE = "openclaw-2026.7.1-protected-consumer"
_ROUTE = "ADM-02/reload/cron-rescan"
_EVIDENCE_SCHEMA = "aragorn/openclaw-protected-cron-rescan-observation/v1"
_EVIDENCE_DIGEST = (
    "sha256:87a93e92d9ffeb4fe6b01abeb496921ca28181db1a601d65b23987de8f9ccc64"
)
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:0c180a2cbb12885ba9b52aba10f444be46029b14fec546d9e29257bdf01287ea"
)
_HELPER_DIGEST = (
    "sha256:44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b"
)
_PROBE_DIGEST = (
    "sha256:db9c038d41735f9dfb16973e293a007abfadd35340b6425dbd7a95a6ea08c27c"
)
_ARCHIVE_HELPER_DIGEST = (
    "sha256:638a06723ea7f500f159f6e784034c755b08e921a3a25ba6ec3e3bf7ce38527f"
)
_PROMPT_HELPER_DIGEST = (
    "sha256:99e50bd0b18723a0bb37ca8afea04ef8b40c6fd3e159c6e17f26320f4f7c586c"
)
_SHARED_HELPER_DIGEST = (
    "sha256:adf90754909150fba60b99b1b890e0815c2b5d081ea32dd5b5a698b1f0dfb50b"
)
_CONFIG_DIGEST = archive._CONFIG_DIGEST
_CONFIG_CANONICAL_DIGEST = archive._CONFIG_CANONICAL_DIGEST
_PROFILE_DIGEST = archive._PROFILE_DIGEST
_PROFILE_CANONICAL_DIGEST = (
    "sha256:e8acb3faef0a04dc542e59b8ed6a5e02ccfba2f4b178a25b6cbe37b19bb64f1d"
)
_TARGET_DIGEST = archive._TARGET_DIGEST
_TARGET_TREE_DIGEST = archive._TARGET_TREE_DIGEST
_RUNTIME_TREE = archive._RUNTIME_TREE
_OPENCLAW_DIGEST = archive._OPENCLAW_DIGEST
_EVIDENCE_BYTES = 66_144
_CONFIG = "/profile/config/openclaw.json"
_SESSION_STORE = "/profile/state/agents/main/sessions/sessions.json"
_CRON_NAME = "Aragorn protected cron rescan probe"
_TARGET_NAME = "requesting-code-review"
_UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_RUN_ID = re.compile(
    r"manual:([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}):([0-9]{13}):1"
)
_MODULES = {
    "cron": (
        33_974,
        "sha256:0e3346d4397db7675073c7f80599aa312a1819b0f5a6480a8ba194b296c78144",
        "/runtime/lib/node_modules/openclaw/dist/cron-BoFeDMVi.js",
    ),
    "cron_snapshot": (
        53,
        "sha256:15050c3de10192ae1190d0aa596d34c2163897948a360fe0494929e171a01967",
        "/runtime/lib/node_modules/openclaw/dist/cron-snapshot.runtime.js",
    ),
    "cron_snapshot_implementation": (
        450,
        "sha256:fb9c29ca637b42389355d627c5e8a209a8d1ebb51b14432a462d9734f00e3665",
        (
            "/runtime/lib/node_modules/openclaw/dist/"
            "cron-snapshot.runtime-xn4WDHsg.js"
        ),
    ),
    "isolated_agent": (
        59_535,
        "sha256:7330ff0387ffde3117c50752d5c656a522b2f32a5110cb494bdc1af2c106eb11",
        "/runtime/lib/node_modules/openclaw/dist/isolated-agent-wBFsap3y.js",
    ),
    "prompt_blobs": (
        6_621,
        "sha256:24164fbc0679c4eb55476a0bcbd2325660f59a47577509f838c682eb516e0553",
        (
            "/runtime/lib/node_modules/openclaw/dist/"
            "skill-prompt-blobs-zJRX9N65.js"
        ),
    ),
    "run_session_state": (
        18_238,
        "sha256:aa5dad173c4d37034c0414c72093d0492009de77ff274ba4d2f7b3d509dc3817",
        (
            "/runtime/lib/node_modules/openclaw/dist/"
            "run-session-state-r5DnSgVq.js"
        ),
    ),
    "session": (
        5_884,
        "sha256:59a2138c9906cffe26e67ad662d1a35d835c10d8d8742a2cb928fc529df81e3b",
        "/runtime/lib/node_modules/openclaw/dist/session-B4NuLEbl.js",
    ),
    "session_snapshot": (
        3_163,
        "sha256:0d93f74fca9a9f8a062d9e03953eda42419ceab49b296e194fd2ed510eb29eec",
        (
            "/runtime/lib/node_modules/openclaw/dist/"
            "session-snapshot-mFoFiIO4.js"
        ),
    ),
    "workspace_skills": (
        47_738,
        "sha256:ee73b5621ff0fa5d198cb39a54eb6fa332d1f96897e4151538415eef7a72846c",
        "/runtime/lib/node_modules/openclaw/dist/workspace-BKXau6p-.js",
    ),
}
_LIMITATIONS = [
    "EXACT_PINNED_PROFILE_AND_SINGLE_CAPTURE_ONLY",
    "EXACT_PROTECTED_ISOLATED_CRON_SNAPSHOT_BUILT_BEFORE_MODEL_RESOLUTION",
    "PERSIST_BEFORE_MODEL_ORDER_DERIVED_FROM_DYNAMIC_TIMESTAMPS",
    "NINE_LIVE_SOURCE_MODULE_DIGESTS_PINNED_WITHOUT_RETAINED_COMPILED_CLOSURE",
    "BASE_CRON_SESSION_ENTRY_HAS_NO_SESSION_ID",
    "NATIVE_PROVIDER_REQUEST_NOT_OBSERVED",
    "TERMINAL_MODEL_NOT_FOUND_EXPECTED_AFTER_SNAPSHOT_PERSISTENCE",
    "CRON_JOB_REMOVED_SESSION_STATE_RETAINED_ONLY_IN_EPHEMERAL_TMPFS",
    "PROTECTED_SOURCE_CONFIGURATION_RUNTIME_AND_GATEWAY_PRESERVED",
    "NATIVE_ROUTE_OBSERVATION_NOT_BROKER_MEDIATED",
    "DOCKER_CONTROL_PLANE_NOT_INDEPENDENTLY_ATTESTED",
    "OTHER_ADMISSION_ROUTES_NOT_QUALIFIED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "PHASE3_RUN_AND_EDR_AUTHORITY_NOT_ESTABLISHED",
]

_MOUNTS = [
    {
        "destination": "/probe",
        "read_only": True,
        "volume": "aragorn-openclaw-p42-cron-probe-v7",
    },
    {
        "destination": "/profile/config",
        "read_only": True,
        "volume": "aragorn-openclaw-p3-archive-config-v1",
    },
    {
        "destination": "/profile/home/.agents/skills",
        "read_only": True,
        "volume": "aragorn-openclaw-p3-archive-guard-v1",
    },
    {
        "destination": "/profile/state/extensions",
        "read_only": True,
        "volume": "aragorn-openclaw-p3-archive-guard-v1",
    },
    {
        "destination": "/profile/state/plugin-skills",
        "read_only": True,
        "volume": "aragorn-openclaw-p3-archive-guard-v1",
    },
    {
        "destination": "/profile/state/skills",
        "read_only": True,
        "volume": "aragorn-openclaw-p3-archive-guard-v1",
    },
    {
        "destination": "/profile/workspace/.agents/skills",
        "read_only": True,
        "volume": "aragorn-openclaw-p3-archive-guard-v1",
    },
    {
        "destination": "/profile/workspace/skills",
        "read_only": True,
        "volume": "aragorn-openclaw-p3-archive-target-v1",
    },
    {
        "destination": "/runtime",
        "read_only": True,
        "volume": "aragorn-openclaw-2026-7-1-runtime",
    },
]
_CONTAINMENT = {
    "capabilities_dropped": ["ALL"],
    "cgroup_namespace_mode": "private",
    "command": [
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
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
    ],
    "container_id": (
        "cc58332fa63f2af588c957367106794f0cb6a5deb37bd5776217a78da696e564"
    ),
    "container_name": "aragorn-openclaw-p42-cron-rescan-v7",
    "container_started_at": "2026-08-09T07:35:13.606058164Z",
    "cpu_limit": 1_000_000_000,
    "effective_user": "1000:1000",
    "environment": [
        "HOME=/profile/home",
        "OPENCLAW_CONFIG_PATH=/profile/config/openclaw.json",
        "OPENCLAW_DISABLE_BUNDLED_PLUGINS=1",
        "OPENCLAW_NO_RESPAWN=1",
        "OPENCLAW_SKIP_CHANNELS=1",
        "OPENCLAW_SKIP_PROVIDERS=1",
        "OPENCLAW_STATE_DIR=/profile/state",
    ],
    "gateway_pid": 1,
    "gateway_start_time_ticks": "25794764",
    "gateway_token_present": True,
    "hostname": "aragorn-p42-cron-rescan-v7",
    "image_digest": (
        "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
    ),
    "ipc_mode": "private",
    "memory_limit": 1_073_741_824,
    "memory_swap_limit": 1_073_741_824,
    "mounts": _MOUNTS,
    "network_mode": "none",
    "no_new_privileges": True,
    "pids_limit": 128,
    "privileged": False,
    "read_only_root_filesystem": True,
    "restart_count": 0,
    "supplementary_groups": ["982"],
    "tmpfs": {
        "/profile/home": (
            "rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=1000,gid=1000"
        ),
        "/profile/state": (
            "rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=1000,gid=1000"
        ),
        "/profile/workspace": (
            "rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=1000,gid=1000"
        ),
        "/tmp": "rw,noexec,nosuid,nodev,size=256m,mode=1777",
    },
    "ulimits": [{"Hard": 256, "Name": "nofile", "Soft": 256}],
}


def verify_openclaw_protected_cron_rescan(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> dict[str, Any]:
    """Qualify one exact isolated cron rescan without aggregate authority."""

    try:
        helper_digests = {
            "archive": _implementation_digest(archive),
            "prompt": _implementation_digest(prompt),
            "shared": _implementation_digest(shared),
        }
        if helper_digests != {
            "archive": _ARCHIVE_HELPER_DIGEST,
            "prompt": _PROMPT_HELPER_DIGEST,
            "shared": _SHARED_HELPER_DIGEST,
        }:
            raise AdmissionEvidenceError("protected helper implementation changed")
        shared.validate_openclaw_protected_consumer_profile(
            route_profile,
            route_inventory=route_inventory,
            runtime_candidates=runtime_candidates,
        )
        if canonical_digest(source_receipt) != _RECEIPT_CANONICAL_DIGEST:
            raise AdmissionEvidenceError("cron rescan retention receipt changed")

        evidence = _read_exact(evidence_cas, _EVIDENCE_DIGEST, _EVIDENCE_SCHEMA)
        profile_raw = canonical_json(dict(route_profile)) + b"\n"
        if (
            _digest(profile_raw) != _PROFILE_DIGEST
            or canonical_digest(route_profile) != _PROFILE_CANONICAL_DIGEST
        ):
            raise AdmissionEvidenceError("protected-consumer profile changed")
        archive._read_source_bytes(
            evidence_cas, _PROFILE_DIGEST, profile_raw, "protected-consumer profile"
        )
        helper_raw = archive._read_source_bytes(
            evidence_cas, _HELPER_DIGEST, None, "protected observation helper"
        )
        probe_raw = archive._read_source_bytes(
            evidence_cas, _PROBE_DIGEST, None, "protected cron rescan probe"
        )
        config_raw = archive._read_source_bytes(
            evidence_cas, _CONFIG_DIGEST, None, "protected configuration"
        )
        target_raw = archive._read_source_bytes(
            evidence_cas,
            _TARGET_DIGEST,
            archive._TARGET_BYTES,
            "protected active skill",
        )
        _verify_source_closure(
            source_receipt,
            evidence,
            profile_raw=profile_raw,
            helper_raw=helper_raw,
            probe_raw=probe_raw,
            config_raw=config_raw,
            target_raw=target_raw,
        )
        _verify_action(evidence, source_receipt)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        CASError,
        IndexError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid protected cron rescan evidence: {exc}"
        ) from exc

    return {
        "assurance": "SEMANTICALLY_VERIFIED_EXACT_PROFILE_PROTECTED_CRON_RESCAN",
        "bindings": {
            "configuration_digest": _CONFIG_DIGEST,
            "existing_target_digest": _TARGET_DIGEST,
            "helper_implementation_digest": _HELPER_DIGEST,
            "probe_implementation_digest": _PROBE_DIGEST,
            "profile_digest": _PROFILE_DIGEST,
            "protected_archive_helper_implementation_digest": helper_digests[
                "archive"
            ],
            "protected_prompt_helper_implementation_digest": helper_digests[
                "prompt"
            ],
            "runtime_tree_digest": _RUNTIME_TREE["tree_digest"],
            "shared_verifier_implementation_digest": helper_digests["shared"],
            "source_evidence_digest": _EVIDENCE_DIGEST,
            "source_receipt_canonical_digest": _RECEIPT_CANONICAL_DIGEST,
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "admission_profile_eligible": False,
            "installer_work_eligible": False,
            "phase3_exit_eligible": False,
            "status": "ROUTE_PASS",
        },
        "limitations": list(_LIMITATIONS),
        "profile": _PROFILE,
        "route": {
            "id": _ROUTE,
            "observed_outcome": (
                "EXACT_PROTECTED_ISOLATED_CRON_SNAPSHOT_BUILT_BEFORE_MODEL_RESOLUTION"
            ),
            "status": "PASS",
        },
        "runtime": dict(route_profile["runtime"]),
        "schema": "aragorn/admission-protected-cron-rescan-route-qualification/v1",
        "source_recorded_at": evidence["recorded_at"],
    }


def _implementation_digest(module: Any) -> str:
    return _digest(Path(module.__file__).read_bytes())


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_source_closure(
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
    *,
    profile_raw: bytes,
    helper_raw: bytes,
    probe_raw: bytes,
    config_raw: bytes,
    target_raw: bytes,
) -> None:
    expected_inputs = {
        "configuration": {
            "bytes": len(config_raw),
            "canonical_digest": _CONFIG_CANONICAL_DIGEST,
            "digest": _CONFIG_DIGEST,
            "path": (
                "benchmark/admission/openclaw-v2026.7.1/"
                "protected-route-config-v1.json"
            ),
        },
        "existing_target": {
            "bytes": len(target_raw),
            "digest": _TARGET_DIGEST,
            "path": "benchmark/fixtures/phase3-protected-archive-existing/SKILL.md",
        },
        "helper": {
            "bytes": len(helper_raw),
            "digest": _HELPER_DIGEST,
            "path": (
                "benchmark/admission/openclaw-v2026.7.1/"
                "protected-observation-v1.mjs"
            ),
        },
        "probe": {
            "bytes": len(probe_raw),
            "digest": _PROBE_DIGEST,
            "path": (
                "benchmark/admission/openclaw-v2026.7.1/"
                "protected-cron-rescan-probe.mjs"
            ),
        },
        "profile": {
            "bytes": len(profile_raw),
            "canonical_digest": _PROFILE_CANONICAL_DIGEST,
            "digest": _PROFILE_DIGEST,
            "path": (
                "benchmark/admission/openclaw-v2026.7.1/"
                "protected-consumer-profile-v1.json"
            ),
        },
    }
    expected_runtime = {
        "commit": "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
        "name": "openclaw",
        "openclaw_digest": _OPENCLAW_DIGEST,
        "runtime_tree": _RUNTIME_TREE,
        "version": "2026.7.1",
    }
    if (
        receipt["schema"]
        != "aragorn/phase3-openclaw-protected-cron-rescan-retention/v1"
        or receipt["assurance"]
        != "OPERATOR_RETAINED_RAW_OBSERVATION_NOT_CONFORMANCE_AUTHORITY"
        or receipt["status"] != "RAW_OBSERVATION_ONLY"
        or receipt["admission_profile_eligible"] is not False
        or receipt["aggregate_admission_eligible"] is not False
        or receipt["installer_work_eligible"] is not False
        or receipt["phase3_exit_eligible"] is not False
        or receipt["results"]
        != {"fail": [], "not_tested": [], "observed": [_ROUTE], "pass": []}
        or receipt["evidence"]
        != {
            "bytes": _EVIDENCE_BYTES,
            "digest": _EVIDENCE_DIGEST,
            "path": (
                "benchmark/evidence/"
                "openclaw-v2026.7.1-protected-cron-rescan-2026-08-09.json"
            ),
            "recorded_at": evidence["recorded_at"],
            "run_nonce": evidence["run_nonce"],
        }
        or receipt["inputs"] != expected_inputs
        or receipt["runtime"] != expected_runtime
        or receipt["containment"] != _CONTAINMENT
        or receipt["limitations"]
        != [
            "OBSERVED_IS_NOT_PASS",
            "EXACT_PROTECTED_ISOLATED_CRON_SNAPSHOT_BUILT_BEFORE_MODEL_RESOLUTION",
            "NATIVE_PROVIDER_REQUEST_NOT_OBSERVED",
            "TERMINAL_MODEL_NOT_FOUND_EXPECTED_AFTER_SNAPSHOT_PERSISTENCE",
            "CRON_JOB_REMOVED_SESSION_STATE_RETAINED_ONLY_IN_EPHEMERAL_TMPFS",
            "PROTECTED_SOURCE_CONFIGURATION_RUNTIME_AND_GATEWAY_PRESERVED",
            "SINGLE_ROUTE_SINGLE_CAPTURE",
            "NO_AGGREGATE_ADMISSION_INSTALLER_PHASE3_OR_EDR_AUTHORITY",
        ]
    ):
        raise AdmissionEvidenceError("cron rescan source closure changed")

    config = shared.load_runtime_profile(config_raw)
    if (
        canonical_json(config) + b"\n" != config_raw
        or canonical_digest(config) != _CONFIG_CANONICAL_DIGEST
        or evidence["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or evidence["implementation_digests"]
        != {"helper": _HELPER_DIGEST, "probe": _PROBE_DIGEST}
        or evidence["runtime_binding"]
        != {
            "commit": "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": _OPENCLAW_DIGEST,
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": _RUNTIME_TREE["tree_digest"],
            "version": "2026.7.1",
        }
        or re.fullmatch(r"[0-9a-f]{32}", evidence["run_nonce"]) is None
    ):
        raise AdmissionEvidenceError("cron rescan source identity changed")


def _verify_boundary(boundary: Mapping[str, Any]) -> None:
    if (
        set(boundary)
        != {"configuration", "effective_identity", "probe", "ready", "roots", "runtime"}
        or boundary["ready"] is not True
        or boundary["effective_identity"]
        != {"gid": 1000, "groups": [982, 1000], "uid": 1000}
        or set(boundary["roots"]) != set(archive._ROOT_MOUNTS)
    ):
        raise AdmissionEvidenceError("cron rescan protected boundary changed")
    for name, (target, source, entries) in archive._ROOT_MOUNTS.items():
        archive._verify_ro_mount(
            boundary["roots"][name],
            target=target,
            source=source,
            uid=0,
            gid=982,
            mode="750",
            entries=entries,
        )
    archive._verify_ro_mount(
        boundary["probe"],
        target="/probe",
        source="/docker/volumes/aragorn-openclaw-p42-cron-probe-v7/_data",
        uid=0,
        gid=0,
        mode="755",
        entries=[
            "protected-cron-rescan-probe.mjs",
            "protected-observation-v1.mjs",
        ],
    )
    archive._verify_ro_mount(
        boundary["configuration"]["mount"],
        target="/profile/config",
        source="/docker/volumes/aragorn-openclaw-p3-archive-config-v1/_data",
        uid=0,
        gid=982,
        mode="750",
        entries=["openclaw.json"],
    )
    archive._verify_ro_mount(
        boundary["runtime"],
        target="/runtime",
        source="/docker/volumes/aragorn-openclaw-2026-7-1-runtime/_data",
        uid=0,
        gid=0,
        mode="755",
        entries=["bin", "lib"],
    )
    config = boundary["configuration"]
    if (
        config["ready"] is not True
        or config["canonical_digest"] != _CONFIG_CANONICAL_DIGEST
        or canonical_digest(config["document"]) != _CONFIG_CANONICAL_DIGEST
        or config["file"]["path"] != _CONFIG
        or config["file"]["type"] != "file"
        or config["file"]["uid"] != 0
        or config["file"]["gid"] != 982
        or config["file"]["mode"] != "440"
        or config["file"]["nlink"] != 1
        or config["file"]["size"] != 316
        or config["file"]["digest"] != _CONFIG_DIGEST
        or config["file"]["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("cron rescan protected configuration changed")


def _verify_config_tree(tree: Mapping[str, Any]) -> None:
    root = tree["root"]
    entries = tree["entries"]
    if (
        tree["ready"] is not True
        or tree["tree_digest"]
        != "sha256:25515c58a071faa82a7206eca9cc9263e612cd108271f70c555ad057218050d7"
        or root["path"] != "/profile/config"
        or root["type"] != "directory"
        or root["uid"] != 0
        or root["gid"] != 982
        or root["mode"] != "750"
        or root["entries"] != ["openclaw.json"]
        or root["entry_count"] != 1
        or root["entries_truncated"] is not False
        or len(entries) != 1
        or entries[0]["path"] != "openclaw.json"
        or entries[0]["type"] != "file"
        or entries[0]["uid"] != 0
        or entries[0]["gid"] != 982
        or entries[0]["mode"] != "440"
        or entries[0]["nlink"] != 1
        or entries[0]["size"] != 316
        or entries[0]["digest"] != _CONFIG_DIGEST
        or entries[0]["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("cron rescan configuration tree changed")


def _verify_protected_root_trees(trees: Mapping[str, Any]) -> None:
    if set(trees) != set(archive._ROOT_MOUNTS):
        raise AdmissionEvidenceError("cron rescan protected roots changed")
    empty_digest = (
        "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
    )
    for name, (path, _, entries) in archive._ROOT_MOUNTS.items():
        tree = trees[name]
        root = tree["root"]
        if (
            tree["ready"] is not True
            or root["path"] != path
            or root["type"] != "directory"
            or root["uid"] != 0
            or root["gid"] != 982
            or root["mode"] != "750"
            or root["entries"] != entries
            or root["entry_count"] != len(entries)
            or root["entries_truncated"] is not False
        ):
            raise AdmissionEvidenceError(f"cron rescan root changed: {name}")
        if name != "workspace_skills" and (
            tree["tree_digest"] != empty_digest or tree["entries"] != []
        ):
            raise AdmissionEvidenceError(f"cron rescan empty root changed: {name}")
    workspace = trees["workspace_skills"]
    if (
        workspace["tree_digest"]
        != "sha256:ad63540172f4cb620a13cfb6b5314bdae1b1193354b02c9b3b710975c4c467cd"
        or len(workspace["entries"]) != 2
        or workspace["entries"][0]["path"] != _TARGET_NAME
        or workspace["entries"][0]["type"] != "directory"
        or workspace["entries"][1]["path"] != f"{_TARGET_NAME}/SKILL.md"
        or workspace["entries"][1]["type"] != "file"
        or workspace["entries"][1]["digest"] != _TARGET_DIGEST
        or workspace["entries"][1]["size"] != len(archive._TARGET_BYTES)
        or workspace["entries"][1]["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("cron rescan workspace tree changed")


def _verify_modules(modules: Mapping[str, Any]) -> None:
    if set(modules) != set(_MODULES):
        raise AdmissionEvidenceError("cron rescan module set changed")
    for name, (size, digest, path) in _MODULES.items():
        value = modules[name]
        observed = value["observed"]
        if (
            value["expected"] != {"bytes": size, "digest": digest, "path": path}
            or observed["path"] != path
            or observed["exists"] is not True
            or observed["type"] != "file"
            or observed["uid"] != 0
            or observed["gid"] != 0
            or observed["mode"] != "644"
            or observed["nlink"] != 1
            or observed["size"] != size
            or observed["digest"] != digest
            or observed["digest_error"] is not None
        ):
            raise AdmissionEvidenceError(f"cron rescan module changed: {name}")


def _verify_version(command: Mapping[str, Any]) -> None:
    if (
        command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ]
        or not shared._command_succeeded_clean(command)
        or not shared._command_output_is_exact(command)
        or command["stdout_excerpt"] != "OpenClaw 2026.7.1 (2d2ddc4)\n"
    ):
        raise AdmissionEvidenceError("cron rescan version changed")


def _native_params(method: str, params: Mapping[str, Any]) -> list[str]:
    return [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        method,
        "--json",
        "--timeout",
        "5000",
        "--params",
        json.dumps(dict(params), sort_keys=True, separators=(",", ":")),
    ]


def _verify_native_call(
    call: Mapping[str, Any], *, method: str, params: Mapping[str, Any]
) -> None:
    command = call["command"]
    if (
        call["params"] != params
        or call["response"]["parsed"] is not True
        or command["argv"] != _native_params(method, params)
        or not shared._command_succeeded_clean(command)
        or not shared._command_output_is_exact(command)
        or json.loads(command["stdout_excerpt"]) != call["response"]["value"]
    ):
        raise AdmissionEvidenceError(f"cron rescan {method} call changed")


def _verify_job(job: Mapping[str, Any]) -> str:
    params = {
        "agentId": "main",
        "delivery": {"mode": "none"},
        "enabled": True,
        "name": _CRON_NAME,
        "payload": {
            "kind": "agentTurn",
            "message": "Inert protected cron rescan observation.",
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
        _UUID4.fullmatch(job_id) is None
        or value["agentId"] != "main"
        or value["enabled"] is not True
        or value["name"] != _CRON_NAME
        or value["sessionTarget"] != "isolated"
        or value["wakeMode"] != "now"
        or value["payload"] != params["payload"]
        or value["delivery"] != {"mode": "none"}
        or value["schedule"]
        != {"anchorMs": created, "everyMs": 86_400_000, "kind": "every"}
        or value["updatedAtMs"] != created
        or value["nextRunAtMs"] != created + 86_400_000
        or value["state"] != {"nextRunAtMs": value["nextRunAtMs"]}
        or not isinstance(created, int)
        or not _command_contains_ms(job["command"], created)
    ):
        raise AdmissionEvidenceError("cron rescan job changed")
    return job_id


def _verify_pre_run_state(
    value: Mapping[str, Any], *, job_id: str, session_store_before: Mapping[str, Any]
) -> None:
    expected_absent = {"exists": False, "path": _SESSION_STORE}
    if (
        value["base_entry_present"] is not False
        or value["base_session_key"] != f"agent:main:cron:{job_id}"
        or value["store"] != expected_absent
        or session_store_before != expected_absent
        or value["store_document_digest"] is not None
        or value["top_level_keys"] != []
        or _time(value["started_at"]) > _time(value["completed_at"])
    ):
        raise AdmissionEvidenceError("cron rescan pre-run state changed")


def _verify_snapshot(value: Mapping[str, Any], *, job_id: str) -> None:
    expected_ref = {
        "algorithm": "sha256",
        "bytes": len(prompt._PROMPT),
        "hash": prompt._PROMPT_DIGEST.removeprefix("sha256:"),
        "version": 1,
    }
    blob = value["blob"]
    entry = value["entry"]
    rendered = value["prompt"]
    snapshot = value["snapshot"]
    metadata = snapshot["metadata"]
    store = value["store"]
    if (
        entry["session_key"] != f"agent:main:cron:{job_id}"
        or entry["label"] != f"Cron: {_CRON_NAME}"
        or _UUID4.fullmatch(entry["lifecycle_revision"]) is None
        or entry["session_id_present"] is not False
        or entry["model"] != "gpt-5.5"
        or entry["model_provider"] != "openai"
        or entry["system_sent"] is not True
        or not isinstance(entry["updated_at"], int)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value["entry_digest"]) is None
        or rendered
        != {
            "bytes": len(prompt._PROMPT),
            "digest": prompt._PROMPT_DIGEST,
            "exact_text": prompt._PROMPT.decode(),
            "inline_prompt_present": False,
            "storage": "promptRef",
        }
        or snapshot["prompt_ref_present"] is not True
        or metadata
        != {
            "promptFormatVersion": 1,
            "skillFilter": [_TARGET_NAME],
            "skills": [{"name": _TARGET_NAME}],
            "version": metadata["version"],
        }
        or not isinstance(metadata["version"], int)
        or snapshot["metadata_digest"] != _digest(canonical_json(metadata))
        or blob["bytes"] != len(prompt._PROMPT)
        or blob["digest"] != prompt._PROMPT_DIGEST
        or blob["prompt_ref"] != expected_ref
        or blob["path"] != prompt._PROMPT_PATH
        or blob["uid"] != 1000
        or blob["gid"] != 1000
        or blob["mode"] != "600"
        or blob["nlink"] != 1
        or re.fullmatch(r"[1-9][0-9]*", blob["mtime_ns"]) is None
        or store["path"] != _SESSION_STORE
        or store["uid"] != 1000
        or store["gid"] != 1000
        or store["mode"] != "600"
        or store["nlink"] != 1
        or store["bytes"] <= 0
        or re.fullmatch(r"sha256:[0-9a-f]{64}", store["digest"]) is None
        or re.fullmatch(r"[1-9][0-9]*", store["mtime_ns"]) is None
    ):
        raise AdmissionEvidenceError("cron rescan snapshot changed")


def _verify_terminal(
    result: Mapping[str, Any],
    *,
    job: Mapping[str, Any],
    run_id: str,
    job_id: str,
    snapshot: Mapping[str, Any],
    terminal_poll: Mapping[str, Any],
) -> None:
    diagnostic = result["diagnostics"]["entries"][0]
    run_match = _RUN_ID.fullmatch(run_id)
    run_epoch = int(run_match.group(2)) if run_match is not None else -1
    session_id = result["sessionId"]
    snapshot_updated = snapshot["entry"]["updated_at"]
    store_mtime = int(snapshot["store"]["mtime_ns"]) // 1_000_000
    blob_mtime = int(snapshot["blob"]["mtime_ns"]) // 1_000_000
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
        or result["jobName"] != _CRON_NAME
        or result["runId"] != run_id
        or _UUID4.fullmatch(session_id) is None
        or result["sessionKey"] != f"agent:main:cron:{job_id}:run:{session_id}"
        or result["deliveryStatus"] != "not-requested"
        or result["diagnostics"]["summary"] != "Unknown model: openai/gpt-5.5"
        or len(result["diagnostics"]["entries"]) != 1
        or diagnostic["message"] != "Unknown model: openai/gpt-5.5"
        or diagnostic["severity"] != "error"
        or diagnostic["source"] != "agent-run"
        or result["runAtMs"] != run_epoch
        or result["nextRunAtMs"] != job["response"]["value"]["nextRunAtMs"]
        or not isinstance(result["durationMs"], int)
        or result["durationMs"] < 0
        or not run_epoch <= snapshot_updated <= store_mtime <= blob_mtime
        or not blob_mtime <= diagnostic["ts"] <= result["ts"]
        or result["ts"]
        > int(_time(terminal_poll["command"]["completed_at"]).timestamp() * 1_000)
    ):
        raise AdmissionEvidenceError("cron rescan terminal result changed")


def _command_contains_ms(command: Mapping[str, Any], epoch_ms: int) -> bool:
    started = int(_time(command["started_at"]).timestamp() * 1_000)
    completed = int(_time(command["completed_at"]).timestamp() * 1_000)
    return started <= epoch_ms <= completed


def _verify_action(evidence: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    if evidence["route"] != {
        "action_id": "cron-rescan",
        "id": _ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }:
        raise AdmissionEvidenceError("cron rescan route selection changed")
    action = evidence["action"]
    before = action["prerequisites"]
    after = action["observations"]
    if (
        action["id"] != "cron-rescan"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["config_lock_before"]
        != {"exists": False, "path": f"{_CONFIG}.lock"}
        or after["config_lock_after"] != before["config_lock_before"]
        or before["config_before"] != before["boundary_before"]["configuration"]
        or after["config_after"] != before["config_before"]
        or after["boundary_after"] != before["boundary_before"]
        or after["config_tree_after"] != before["config_tree_before"]
        or after["protected_root_trees_after"]
        != before["protected_root_trees_before"]
        or after["target_after"] != before["target_before"]
        or after["runtime_tree_after"] != before["runtime_tree_before"]
        or after["openclaw_after"] != before["openclaw_before"]
        or after["gateway_process_after"] != before["gateway_process_before"]
        or after["module_files_after"] != before["module_files_before"]
    ):
        raise AdmissionEvidenceError("cron rescan protected state changed")

    _verify_boundary(before["boundary_before"])
    _verify_config_tree(before["config_tree_before"])
    _verify_protected_root_trees(before["protected_root_trees_before"])
    archive._verify_fixture_tree(
        before["target_before"],
        root_path=archive._TARGET,
        digest=_TARGET_DIGEST,
        size=len(archive._TARGET_BYTES),
        tree_digest=_TARGET_TREE_DIGEST,
    )
    if before["runtime_tree_before"] != _RUNTIME_TREE:
        raise AdmissionEvidenceError("cron rescan runtime tree changed")
    prompt._verify_openclaw(before["openclaw_before"])
    _verify_modules(before["module_files_before"])

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
        raise AdmissionEvidenceError("cron rescan gateway identity changed")

    prompt._verify_discovery(before["discovery_before"])
    prompt._verify_discovery(after["discovery_after"])
    if (
        before["discovery_before"]["response"]
        != after["discovery_after"]["response"]
        or before["discovery_before"]["command"]["stdout_digest"]
        != after["discovery_after"]["command"]["stdout_digest"]
    ):
        raise AdmissionEvidenceError("cron rescan discovery changed")
    prompt._verify_system(before["system_info_before"], gateway)
    prompt._verify_system(after["system_info_after"], gateway)
    _verify_version(before["version"])

    job = after["job"]
    job_id = _verify_job(job)
    pre_run = after["session_state_before_forced_run"]
    _verify_pre_run_state(
        pre_run, job_id=job_id, session_store_before=before["session_store_before"]
    )

    run = after["run"]
    request = run["request"]
    _verify_native_call(
        request, method="cron.run", params={"id": job_id, "mode": "force"}
    )
    run_id = request["response"]["value"].get("runId")
    if (
        request["response"]["value"]
        != {"enqueued": True, "ok": True, "runId": run_id}
        or not isinstance(run_id, str)
        or _RUN_ID.fullmatch(run_id) is None
        or not _command_contains_ms(
            request["command"], int(_RUN_ID.fullmatch(run_id).group(2))
        )
        or run["poll_count"] != len(run["polls"]) == 1
        or run["terminal_poll"] != run["polls"][0]
    ):
        raise AdmissionEvidenceError("cron rescan forced run changed")

    poll = run["terminal_poll"]
    _verify_native_call(poll, method="cron.runs", params={"id": job_id, "limit": 10})
    history = poll["response"]["value"]
    terminal = after["terminal_result"]
    if history != {
        "entries": [terminal],
        "hasMore": False,
        "limit": 10,
        "nextOffset": None,
        "offset": 0,
        "total": 1,
    }:
        raise AdmissionEvidenceError("cron rescan terminal history changed")

    snapshot = after["snapshot"]
    _verify_snapshot(snapshot, job_id=job_id)
    _verify_terminal(
        terminal,
        job=job,
        run_id=run_id,
        job_id=job_id,
        snapshot=snapshot,
        terminal_poll=poll,
    )

    store_after = after["session_store_after"]
    store = snapshot["store"]
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
        raise AdmissionEvidenceError("cron rescan retained session store changed")

    cleanup = after["cleanup"]
    _verify_native_call(cleanup, method="cron.remove", params={"id": job_id})
    if cleanup["response"]["value"] != {"ok": True, "removed": True}:
        raise AdmissionEvidenceError("cron rescan cleanup changed")

    commands = action["commands"]
    expected_commands = [
        before["version"],
        before["system_info_before"]["command"],
        before["discovery_before"]["command"],
        job["command"],
        request["command"],
        poll["command"],
        cleanup["command"],
        after["discovery_after"]["command"],
        after["system_info_after"]["command"],
    ]
    if (
        commands != expected_commands
        or any(
            _time(current["completed_at"]) > _time(next_["started_at"])
            for current, next_ in pairwise(commands)
        )
        or _time(job["command"]["completed_at"]) > _time(pre_run["started_at"])
        or _time(pre_run["completed_at"]) > _time(request["command"]["started_at"])
        or _time(poll["command"]["completed_at"])
        > _time(cleanup["command"]["started_at"])
        or _time(cleanup["command"]["completed_at"])
        > _time(after["discovery_after"]["command"]["started_at"])
        or _time(commands[-1]["completed_at"]) > _time(evidence["recorded_at"])
        or any(
            not shared._command_succeeded_clean(command)
            or not shared._command_output_is_exact(command)
            for command in commands
        )
    ):
        raise AdmissionEvidenceError("cron rescan command causality changed")
