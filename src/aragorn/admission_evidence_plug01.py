"""Semantic verification for retained OpenClaw PLUG-01 route evidence."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from .admission_conformance import (
    AdmissionConformanceError,
    validate_admission_conformance,
)
from .admission_evidence import (
    _EMPTY_DIGEST,
    _MODEL_ACTIVATION_VERSION_STDOUT_BYTES,
    _OPENCLAW_COMMIT,
    _OPENCLAW_PLATFORM_MANIFEST,
    _OPENCLAW_RUNTIME_TREE,
    _UPDATE_RELOAD_COVERAGE_DIGEST,
    _UPDATE_RELOAD_COVERAGE_REASONS,
    _UPDATE_RELOAD_COVERAGE_SCHEMA,
    _UPDATE_RELOAD_INVENTORY_DIGEST,
    AdmissionEvidenceError,
    _canonical_bytes,
    _read_exact,
    _time,
    _verify_successful_config_command,
    verify_openclaw_update_reload_coverage,
)
from .admission_routes import validate_openclaw_2026_7_1_route_inventory
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest

_PLUG01_ACTIVATION_SCHEMA = "aragorn/openclaw-contained-plug01-activation-evidence/v1"
_PLUG01_REPLACEMENT_SCHEMA = "aragorn/openclaw-contained-plug01-replacement-evidence/v1"
_PLUG01_ENV_SCHEMA = "aragorn/openclaw-contained-plug01-environment-evidence/v1"
_UPDATE_RELOAD_COVERAGE_V2_SCHEMA = (
    "aragorn/openclaw-update-reload-route-coverage-evidence/v2"
)
_PLUG01_ACTIVATION_DIGEST = (
    "sha256:c2a2e6f197f228d00129c28b192588bcfa68f12208589c5f5498cbf151de77a8"
)
_PLUG01_REPLACEMENT_DIGEST = (
    "sha256:9ed516ae0ea9f1f4c5f41983d638039e599ab19c66e450a7aef59a5289ffb533"
)
_PLUG01_ENV_DIGEST = (
    "sha256:0307e7229b8d5f6621f38abdfb27a7248fac697d767e376d7c093cd06f928f25"
)
_UPDATE_RELOAD_COVERAGE_V2_DIGEST = (
    "sha256:df34ef52fd06728b2a7633e5f2c19cb463907c5b97cba18a5056485596291600"
)
_UPDATE_RELOAD_V1_RECEIPT_DIGEST = (
    "sha256:0cac93421db41c1069aa5d3923fbfc4f12dcf3e0a5309145bbb94536c23d6004"
)
_PLUG01_IMPLEMENTATION_DIGEST = (
    "sha256:d70fb960c8cc6798815d47c82caf4f1bb9e064d54566ccccb45e76865de284ef"
)
_PLUG01_CONFIGURATION_DIGEST = (
    "sha256:b300b5e650959ad0bc15c4a6a10b6a06941a196595fed8adc41641eb8285dbd6"
)
_PLUG01_FIXTURE_DIGESTS = {
    "allowed": (
        "sha256:e4f885bd577d674f0f5623ddc6968f66447174ddea9b7a5bcf2c2e3b2c931243"
    ),
    "baseline": (
        "sha256:0207695b67d1b3f4bab3f329dca8b28e1ab6c0a43508d0903367778b5188fe16"
    ),
    "blocked": (
        "sha256:fb334a48601179231251fc3444bd084730d516d18ccc482f899a2811cdd795db"
    ),
}
_PLUG01_EVIDENCE_DIGESTS = sorted(
    (
        _PLUG01_ACTIVATION_DIGEST,
        _PLUG01_ENV_DIGEST,
        _PLUG01_REPLACEMENT_DIGEST,
    )
)
_PLUG01_ROUTE_SOURCES = {
    "ADM-02/update/plugin-enable-activation": sorted(
        (_PLUG01_ACTIVATION_DIGEST, _PLUG01_ENV_DIGEST)
    ),
    "ADM-02/update/plugin-force-reinstall": sorted(
        (_PLUG01_ENV_DIGEST, _PLUG01_REPLACEMENT_DIGEST)
    ),
    "ADM-02/reload/plugin-skill-dir-activation": sorted(
        (_PLUG01_ACTIVATION_DIGEST, _PLUG01_ENV_DIGEST)
    ),
}


def verify_openclaw_update_reload_coverage_v2(
    document: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> None:
    """Verify cumulative PLUG-01 route evidence without granting authority."""

    try:
        if (
            set(document)
            != {
                "bindings",
                "decision",
                "profile",
                "properties",
                "recorded_at",
                "schema",
            }
            or document["schema"] != "aragorn/admission-conformance-result/v1"
            or document["profile"] != "admission-conformant/v1"
            or any(
                set(item) != {"id", "scenarios", "status"}
                for item in document["properties"]
            )
            or any(
                set(scenario)
                != {
                    "evidence_digests",
                    "id",
                    "reason_codes",
                    "status",
                }
                for item in document["properties"]
                for scenario in item["scenarios"]
            )
        ):
            raise AdmissionEvidenceError("PLUG-01 receipt shape changed")
        if validate_admission_conformance(document) != "NOT_TESTED" or document[
            "decision"
        ] != {"status": "NOT_TESTED", "installer_work_eligible": False}:
            raise AdmissionEvidenceError(
                "PLUG-01 coverage cannot grant installer authority"
            )
        formal_items = [
            (f"{item['id']}/{scenario['id']}", scenario)
            for item in document["properties"]
            for scenario in item["scenarios"]
        ]
        formal = dict(formal_items)
        if (
            [key for key, _ in formal_items] != list(_UPDATE_RELOAD_COVERAGE_REASONS)
            or any(item["status"] != "NOT_TESTED" for item in formal.values())
            or {key: item["reason_codes"] for key, item in formal.items()}
            != _UPDATE_RELOAD_COVERAGE_REASONS
        ):
            raise AdmissionEvidenceError("PLUG-01 formal claim set changed")
        for key, scenario in formal.items():
            expected = (
                [_UPDATE_RELOAD_COVERAGE_V2_DIGEST]
                if key in {"ADM-02/update", "ADM-02/reload"}
                else []
            )
            if scenario["evidence_digests"] != expected:
                raise AdmissionEvidenceError(
                    f"{key} does not bind the exact PLUG-01 coverage"
                )

        coverage = _read_exact(
            evidence_cas,
            _UPDATE_RELOAD_COVERAGE_V2_DIGEST,
            _UPDATE_RELOAD_COVERAGE_V2_SCHEMA,
        )
        activation = _read_exact(
            evidence_cas,
            _PLUG01_ACTIVATION_DIGEST,
            _PLUG01_ACTIVATION_SCHEMA,
        )
        replacement = _read_exact(
            evidence_cas,
            _PLUG01_REPLACEMENT_DIGEST,
            _PLUG01_REPLACEMENT_SCHEMA,
        )
        environment = _read_exact(
            evidence_cas,
            _PLUG01_ENV_DIGEST,
            _PLUG01_ENV_SCHEMA,
        )
        v1_receipt = _read_exact(
            evidence_cas,
            _UPDATE_RELOAD_V1_RECEIPT_DIGEST,
            "aragorn/admission-conformance-result/v1",
        )
        validate_openclaw_2026_7_1_route_inventory(
            route_inventory,
            runtime_candidates,
        )
        verify_openclaw_update_reload_coverage(
            v1_receipt,
            evidence_cas=evidence_cas,
            route_inventory=route_inventory,
            runtime_candidates=runtime_candidates,
        )
        _verify_plug01_activation(activation)
        _verify_plug01_replacement(replacement)
        _verify_plug01_environment(activation, replacement, environment)
        _verify_update_reload_coverage_v2(
            document,
            coverage,
            activation=activation,
            replacement=replacement,
            environment=environment,
            v1_receipt=v1_receipt,
            evidence_cas=evidence_cas,
            route_inventory=route_inventory,
        )
    except AdmissionEvidenceError:
        raise
    except (
        AdmissionConformanceError,
        AttributeError,
        CASError,
        IndexError,
        KeyError,
        OSError,
        StopIteration,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid retained PLUG-01 coverage: {exc}"
        ) from exc


def _verify_plug01_common(probe: Mapping[str, Any]) -> Mapping[str, Any]:
    if probe[
        "assurance"
    ] != "SELF_REPORTED_CONTAINED_RUNTIME_NOT_INDEPENDENTLY_ATTESTED" or probe[
        "decision"
    ] != {"status": "NOT_TESTED", "installer_work_eligible": False}:
        raise AdmissionEvidenceError("PLUG-01 claim boundary changed")

    adapter = probe["adapter"]
    if (
        set(adapter)
        != {
            "configuration",
            "configuration_digest",
            "implementation_digest",
            "name",
        }
        or adapter["name"] != "openclaw-contained-plug01"
        or adapter["configuration_digest"] != canonical_digest(adapter["configuration"])
        or adapter["configuration_digest"] != _PLUG01_CONFIGURATION_DIGEST
        or adapter["implementation_digest"] != _PLUG01_IMPLEMENTATION_DIGEST
    ):
        raise AdmissionEvidenceError("PLUG-01 adapter identity changed")

    runtime = probe["runtime"]
    version = runtime["version_command"]
    _verify_successful_config_command(
        version,
        [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ],
    )
    if (
        set(runtime) != {"commit", "name", "version", "version_command"}
        or runtime["commit"] != _OPENCLAW_COMMIT
        or runtime["name"] != "OpenClaw"
        or runtime["version"] != "2026.7.1"
        or version["stdout_bytes"] != _MODEL_ACTIVATION_VERSION_STDOUT_BYTES
        or version["stdout_digest"]
        != "sha256:9e98975ff3973bcd88f224e1820a177c3c881f7a46b51b7dc5ec5d050f72607f"
    ):
        raise AdmissionEvidenceError("PLUG-01 runtime identity changed")

    setup = probe["consumed_setup"]
    if set(setup) != {
        "binding",
        "config",
        "fixtures",
        "inspect",
        "link",
        "policy",
        "policy_records",
        "residue",
        "source_write_guard",
        "target",
    }:
        raise AdmissionEvidenceError("PLUG-01 setup projection changed")
    binding = setup["binding"]
    if (
        set(binding) != {"digest", "path", "recorded_at", "schema", "target_digest"}
        or binding["path"] != "/profile/state/plug01-setup.json"
        or binding["schema"] != "aragorn/openclaw-contained-plug01-setup-evidence/v1"
        or binding["target_digest"] != _PLUG01_FIXTURE_DIGESTS["baseline"]
        or re.fullmatch(r"sha256:[0-9a-f]{64}", binding["digest"]) is None
    ):
        raise AdmissionEvidenceError("PLUG-01 setup binding changed")

    entries = [
        {"mode": "444", "path": "index.js", "type": "file"},
        {"mode": "444", "path": "openclaw.plugin.json", "type": "file"},
        {"mode": "444", "path": "package.json", "type": "file"},
        {"mode": "755", "path": "skills", "type": "directory"},
        {
            "mode": "755",
            "path": "skills/aragorn-plug01-skill",
            "type": "directory",
        },
        {
            "mode": "444",
            "path": "skills/aragorn-plug01-skill/SKILL.md",
            "type": "file",
        },
    ]
    fixtures = setup["fixtures"]
    if set(fixtures) != set(_PLUG01_FIXTURE_DIGESTS):
        raise AdmissionEvidenceError("PLUG-01 fixture set changed")
    for name, digest in _PLUG01_FIXTURE_DIGESTS.items():
        if fixtures[name] != {
            "digest": digest,
            "entries": entries,
            "path": f"/sources/{name}-source",
        }:
            raise AdmissionEvidenceError(f"PLUG-01 {name} fixture changed")
    if setup["target"] != {
        "digest": _PLUG01_FIXTURE_DIGESTS["baseline"],
        "entries": entries,
        "path": "/profile/state/extensions/aragorn-plug01",
    }:
        raise AdmissionEvidenceError("PLUG-01 baseline target changed")

    config = setup["config"]
    core = dict(config["document"])
    meta = core.pop("meta")
    config_identity = {
        ("sha256:fff6502e697c9fe8efbd84ca80b1cc7777aa458e74b4b7f7697955b9894bdc18"): {
            "digest": (
                "sha256:6809106e6d10e4568fbb799d06ac07a2310484cc0d506c2d89b5eae858681b3f"
            ),
            "size": 1213,
        },
        ("sha256:4359fd089a52cac98f27a4278e7d6f244d2de29fa5b7a8f85b052a61dd01876f"): {
            "digest": (
                "sha256:5f2000860035fe462b0edb41ba8efd48ef34c9b21f48873c79030a2fd72cebfd"
            ),
            "size": 1213,
        },
    }.get(binding["digest"])
    if (
        set(config) != {"core_digest", "digest", "document", "mode", "path", "size"}
        or config_identity is None
        or {key: config[key] for key in ("digest", "size")} != config_identity
        or core != adapter["configuration"]
        or config["core_digest"] != canonical_digest(core)
        or config["core_digest"] != _PLUG01_CONFIGURATION_DIGEST
        or config["mode"] != "600"
        or config["path"] != "/profile/state/openclaw.json"
        or set(meta) != {"lastTouchedAt", "lastTouchedVersion"}
        or meta["lastTouchedVersion"] != "2026.7.1"
        or _time(meta["lastTouchedAt"]) > _time(binding["recorded_at"])
    ):
        raise AdmissionEvidenceError("PLUG-01 setup configuration changed")

    inspect = setup["inspect"]
    if (
        inspect["valid"] is not True
        or inspect["install"]["install_path"]
        != "/profile/state/extensions/aragorn-plug01"
        or inspect["install"]["source"] != "path"
        or inspect["install"]["source_path"] != "/sources/baseline-source"
        or inspect["install"]["version"] != "1.0.0"
        or inspect["plugin"]
        != {
            "id": "aragorn-plug01",
            "source": "/profile/state/extensions/aragorn-plug01/index.js",
            "status": "disabled",
            "version": "1.0.0",
        }
    ):
        raise AdmissionEvidenceError("PLUG-01 setup install changed")

    records = setup["policy_records"]
    routes = [
        (
            "baseline-source",
            "/sources/baseline-source",
            {
                "packageName": "@aragorn/plug01-fixture",
                "type": "plugin-package",
                "version": "1.0.0",
            },
            {
                "contentType": "package",
                "extensions": ["./index.js"],
                "manifestId": "aragorn-plug01",
                "packageName": "@aragorn/plug01-fixture",
                "pluginId": "aragorn-plug01",
                "version": "1.0.0",
            },
        ),
        (
            "baseline-installed-dependency-tree",
            None,
            {"type": "plugin-dependency-tree"},
            {
                "contentType": "dependency-tree",
                "pluginId": "aragorn-plug01",
            },
        ),
    ]
    if not isinstance(records, list) or len(records) != len(routes):
        raise AdmissionEvidenceError("PLUG-01 setup policy count changed")
    for record, (route, source_path, origin, plugin) in zip(
        records, routes, strict=True
    ):
        request = record["request"]
        actual_path = record["source"]["path"]
        if source_path is None:
            if (
                re.fullmatch(
                    r"/profile/state/extensions/\.openclaw-install-stage-[A-Za-z0-9]+",
                    actual_path,
                )
                is None
            ):
                raise AdmissionEvidenceError("PLUG-01 stage path changed")
        elif actual_path != source_path:
            raise AdmissionEvidenceError("PLUG-01 source path changed")
        if (
            record["decision"] != "allow"
            or record["route"] != route
            or record["oversized"] is not False
            or record["parse_error"] is not None
            or record["protocol_version"] != 1
            or not isinstance(record["input_bytes"], int)
            or record["input_bytes"] <= 0
            or re.fullmatch(r"sha256:[0-9a-f]{64}", record["input_digest"]) is None
            or _time(record["recorded_at"]) > _time(binding["recorded_at"])
            or record["source"]
            != {
                "digest": _PLUG01_FIXTURE_DIGESTS["baseline"],
                "entries": entries,
                "path": actual_path,
            }
            or request["protocolVersion"] != 1
            or request["openclawVersion"] != "2026.7.1"
            or request["origin"] != origin
            or request["plugin"] != plugin
            or request["request"]
            != {
                "kind": "plugin-dir",
                "mode": "install",
                "requestedSpecifier": "/sources/baseline-source",
            }
            or request["source"]
            != {
                "authority": "user",
                "kind": "local-path",
                "mutable": True,
                "network": False,
            }
            or request["sourcePath"] != actual_path
            or request["sourcePathKind"] != "directory"
            or request["targetName"] != "aragorn-plug01"
            or request["targetType"] != "plugin"
        ):
            raise AdmissionEvidenceError("PLUG-01 setup policy record changed")
    expected_routes = [
        {
            "decision": record["decision"],
            "input_digest": record["input_digest"],
            "route": record["route"],
            "source_path": record["source"]["path"],
        }
        for record in records
    ]
    policy_raw = b"".join(_canonical_bytes(record) + b"\n" for record in records)
    policy = setup["policy"]
    if (
        policy["count"] != len(records)
        or policy["routes"] != expected_routes
        or policy["digest"] != "sha256:" + hashlib.sha256(policy_raw).hexdigest()
        or policy["path"] != "/profile/state/plug01-policy-requests.jsonl"
    ):
        raise AdmissionEvidenceError("PLUG-01 setup policy summary changed")
    if (
        setup["link"]
        != {
            "exists": False,
            "path": "/profile/state/plugin-skills/aragorn-plug01-skill",
        }
        or setup["residue"]
        != {
            "clean": True,
            "entries": ["aragorn-plug01"],
            "residue": [],
            "root": "/profile/state/extensions",
        }
        or setup["source_write_guard"]["blocked"] is not True
        or setup["source_write_guard"]["attempts"]
        != [
            {
                "blocked": True,
                "code": "EACCES",
                "path": "/sources/baseline-source/package.json",
            },
            {
                "blocked": True,
                "code": "EROFS",
                "path": "/sources/baseline-source/.write-probe",
            },
        ]
    ):
        raise AdmissionEvidenceError("PLUG-01 setup guard or residue changed")
    return setup


def _verify_plug01_config(
    snapshot: Mapping[str, Any],
    *,
    adapter_configuration: Mapping[str, Any],
    digest: str,
    enabled: bool,
    size: int,
) -> None:
    core = dict(snapshot["document"])
    meta = core.pop("meta")
    expected = json.loads(json.dumps(adapter_configuration))
    expected["plugins"]["entries"]["aragorn-plug01"]["enabled"] = enabled
    if (
        set(snapshot) != {"core_digest", "digest", "document", "mode", "path", "size"}
        or core != expected
        or snapshot["core_digest"] != canonical_digest(core)
        or snapshot["digest"] != digest
        or snapshot["mode"] != "600"
        or snapshot["path"] != "/profile/state/openclaw.json"
        or snapshot["size"] != size
        or set(meta) != {"lastTouchedAt", "lastTouchedVersion"}
        or meta["lastTouchedVersion"] != "2026.7.1"
    ):
        raise AdmissionEvidenceError("PLUG-01 configuration transition changed")


def _verify_plug01_status(
    status: Mapping[str, Any],
    expected_matches: list[dict[str, Any]],
) -> None:
    _verify_successful_config_command(
        status["command"],
        [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            "skills.status",
            "--json",
            "--timeout",
            "5000",
        ],
    )
    if status["matches"] != expected_matches:
        raise AdmissionEvidenceError("PLUG-01 skill visibility changed")


def _plug01_skill_match() -> dict[str, Any]:
    return {
        "blocked_by_agent_filter": False,
        "command_visible": True,
        "disabled": False,
        "eligible": True,
        "file_path": ("/profile/state/plugin-skills/aragorn-plug01-skill/SKILL.md"),
        "model_visible": True,
        "name": "aragorn-plug01-skill",
        "source": "openclaw-extra",
        "user_invocable": True,
    }


def _verify_plug01_activation(probe: Mapping[str, Any]) -> None:
    if set(probe) != {
        "adapter",
        "assurance",
        "consumed_setup",
        "decision",
        "gateway",
        "gateway_log",
        "recorded_at",
        "runtime",
        "scenarios",
        "schema",
        "write_guard",
    }:
        raise AdmissionEvidenceError("PLUG-01 activation envelope changed")
    setup = _verify_plug01_common(probe)
    scenarios = probe["scenarios"]
    if [(item["id"], item["status"]) for item in scenarios] != [
        ("ADM-02/update/plugin-enable-activation", "PASS"),
        ("ADM-02/reload/plugin-skill-dir-activation", "PASS"),
    ]:
        raise AdmissionEvidenceError("PLUG-01 activation routes changed")

    update = scenarios[0]["evidence"]
    if set(update) != {
        "config_after",
        "config_before",
        "enable_command",
        "install_after",
        "policy_after",
        "policy_before",
        "process_after",
        "process_before",
    }:
        raise AdmissionEvidenceError("PLUG-01 enable evidence changed")
    command = update["enable_command"]
    _verify_successful_config_command(
        command,
        [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "plugins",
            "enable",
            "aragorn-plug01",
        ],
    )
    _verify_plug01_config(
        update["config_before"],
        adapter_configuration=probe["adapter"]["configuration"],
        digest=(
            "sha256:6809106e6d10e4568fbb799d06ac07a2310484cc0d506c2d89b5eae858681b3f"
        ),
        enabled=False,
        size=1213,
    )
    _verify_plug01_config(
        update["config_after"],
        adapter_configuration=probe["adapter"]["configuration"],
        digest=(
            "sha256:3cf17ed3127a5f11d6ad2868a74f4f3e2bbf895c314f3cf086ec48559ce0dbd6"
        ),
        enabled=True,
        size=1212,
    )
    expected_install = json.loads(json.dumps(setup["inspect"]))
    expected_install["plugin"]["status"] = "loaded"
    process = update["process_before"]
    if (
        update["config_before"] != setup["config"]
        or update["policy_before"] != setup["policy"]
        or update["policy_after"] != setup["policy"]
        or update["install_after"] != expected_install
        or update["process_after"] != process
        or process["alive"] is not True
        or not isinstance(process["pid"], int)
        or process["pid"] <= 1
        or process["system_info_pid"] != process["pid"]
        or _time(command["started_at"])
        > _time(update["config_after"]["document"]["meta"]["lastTouchedAt"])
        or _time(update["config_after"]["document"]["meta"]["lastTouchedAt"])
        > _time(command["completed_at"])
    ):
        raise AdmissionEvidenceError("PLUG-01 enable transition changed")

    reload = scenarios[1]["evidence"]
    if set(reload) != {
        "activation",
        "config_detected",
        "hot_reload_applied",
        "link_after",
        "link_before",
        "no_restart",
        "status_before",
        "target_after",
        "target_before",
    }:
        raise AdmissionEvidenceError("PLUG-01 reload evidence changed")
    _verify_plug01_status(reload["status_before"], [])
    if reload["activation"]["poll_count"] != 1:
        raise AdmissionEvidenceError("PLUG-01 activation poll changed")
    _verify_plug01_status(
        reload["activation"]["status"],
        [_plug01_skill_match()],
    )
    expected_link = {
        "digest": (
            "sha256:75d05025b6b8a30acffed758f1174da01c0830e03f6edf3c5dd5929fbe4a0102"
        ),
        "exists": True,
        "fixture": "baseline",
        "path": "/profile/state/plugin-skills/aragorn-plug01-skill",
        "realpath": (
            "/profile/state/extensions/aragorn-plug01/skills/aragorn-plug01-skill"
        ),
        "symlink_target": (
            "/profile/state/extensions/aragorn-plug01/skills/aragorn-plug01-skill"
        ),
    }
    if (
        reload["link_before"] != setup["link"]
        or reload["link_after"] != expected_link
        or reload["target_before"] != setup["target"]
        or reload["target_after"] != setup["target"]
        or reload["no_restart"]
        != {"passed": True, "ready_after": [], "restart_records": []}
    ):
        raise AdmissionEvidenceError("PLUG-01 hot activation state changed")

    log = probe["gateway_log"]
    markers = log["marker_records"]
    if (
        log["ready_count"] != 1
        or log["restart_mode_count"] != 0
        or len(markers) != 3
        or [item["message"] for item in markers]
        != [
            "gateway ready",
            (
                "config change detected; evaluating reload "
                "(plugins.entries.aragorn-plug01.enabled, meta.lastTouchedAt)"
            ),
            ("config hot reload applied (plugins.entries.aragorn-plug01.enabled)"),
        ]
        or reload["config_detected"] != markers[1]
        or reload["hot_reload_applied"] != markers[2]
        or not (markers[0]["offset"] < markers[1]["offset"] < markers[2]["offset"])
        or not (
            _time(markers[0]["time"])
            < _time(markers[1]["time"])
            <= _time(markers[2]["time"])
        )
        or _time(command["completed_at"]) > _time(markers[1]["time"])
        or _time(markers[2]["time"])
        > _time(reload["activation"]["status"]["command"]["completed_at"])
        or probe["gateway"]["final_log"]["marker_records"][:3] != markers
        or probe["gateway"]["final_log"]["ready_count"] != 1
        or probe["gateway"]["final_log"]["restart_mode_count"] != 0
        or probe["gateway"]["shutdown"]["pid"] != process["pid"]
        or probe["gateway"]["shutdown"]["exit_code"] != 0
        or probe["gateway"]["shutdown"]["signal"] is not None
        or probe["gateway"]["shutdown"]["spawn_error"] is not None
        or _time(probe["recorded_at"])
        < _time(probe["gateway"]["final_log"]["marker_records"][-1]["time"])
    ):
        raise AdmissionEvidenceError("PLUG-01 activation lifecycle changed")
    if probe["write_guard"] != {
        "attempts": [
            {
                "blocked": True,
                "code": "EACCES",
                "path": ("/profile/state/extensions/aragorn-plug01/package.json"),
            },
            {
                "blocked": True,
                "code": "EROFS",
                "path": "/profile/state/extensions/.write-probe",
            },
        ],
        "blocked": True,
    }:
        raise AdmissionEvidenceError("PLUG-01 activation write guard changed")


def _verify_plug01_replacement(probe: Mapping[str, Any]) -> None:
    if set(probe) != {
        "adapter",
        "assurance",
        "consumed_setup",
        "decision",
        "gateway",
        "gateway_log",
        "recorded_at",
        "runtime",
        "scenarios",
        "schema",
    }:
        raise AdmissionEvidenceError("PLUG-01 replacement envelope changed")
    setup = _verify_plug01_common(probe)
    scenarios = probe["scenarios"]
    if [(item["id"], item["status"]) for item in scenarios] != [
        ("ADM-02/update/plugin-force-reinstall", "PASS")
    ]:
        raise AdmissionEvidenceError("PLUG-01 replacement route changed")
    evidence = scenarios[0]["evidence"]
    if set(evidence) != {"allowed", "blocked", "post_restart"}:
        raise AdmissionEvidenceError("PLUG-01 replacement evidence changed")

    blocked = evidence["blocked"]
    command = blocked["command"]
    if (
        set(blocked)
        != {
            "command",
            "config_after",
            "config_before",
            "install_after",
            "install_before",
            "no_restart",
            "policy_after",
            "policy_before",
            "residue_after",
            "target_after",
            "target_before",
        }
        or command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "plugins",
            "install",
            "/sources/blocked-source",
            "--force",
        ]
        or command["exit_code"] != 1
        or command["signal"] is not None
        or command["error"] is not None
        or "blocked by install policy: Aragorn PLUG-01 exact blocked fixture"
        not in command["stderr_excerpt"]
        or blocked["config_before"] != setup["config"]
        or blocked["config_after"] != blocked["config_before"]
        or blocked["install_before"] != setup["inspect"]
        or blocked["install_after"] != blocked["install_before"]
        or blocked["target_before"] != setup["target"]
        or blocked["target_after"] != blocked["target_before"]
        or blocked["policy_before"] != setup["policy"]
        or blocked["policy_after"]["count"] != blocked["policy_before"]["count"] + 1
        or blocked["policy_after"]["count"] != len(blocked["policy_after"]["routes"])
        or blocked["policy_after"]["digest"]
        != "sha256:2615da3313330d54d5617691beed05923e52f8f67749c793ea5ab0bc8ceef372"
        or blocked["policy_after"]["path"]
        != "/profile/state/plug01-policy-requests.jsonl"
        or blocked["policy_after"]["routes"][:-1] != blocked["policy_before"]["routes"]
        or blocked["policy_after"]["routes"][-1]
        != {
            "decision": "block",
            "input_digest": (
                "sha256:b35e8149feaef743293b46d3a96cd3a9698b8123985ba37be4b2bbebf0c458f8"
            ),
            "route": "blocked-source",
            "source_path": "/sources/blocked-source",
        }
        or blocked["residue_after"] != setup["residue"]
        or blocked["no_restart"]
        != {"passed": True, "ready_after": [], "restart_records": []}
        or _time(command["started_at"]) > _time(command["completed_at"])
    ):
        raise AdmissionEvidenceError("PLUG-01 blocked replacement changed")

    allowed = evidence["allowed"]
    command = allowed["command"]
    _verify_successful_config_command(
        command,
        [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "plugins",
            "install",
            "/sources/allowed-source",
            "--force",
        ],
    )
    _verify_plug01_config(
        allowed["config_after"],
        adapter_configuration=probe["adapter"]["configuration"],
        digest=(
            "sha256:f4096929c46aa026ffa0338b5e0d951770cacf9d560a5851fd7bf7aac01eb4dc"
        ),
        enabled=True,
        size=1212,
    )
    stage_path = allowed["recorded_stage_path"]
    install = allowed["install_after"]
    if (
        set(allowed)
        != {
            "command",
            "config_after",
            "install_after",
            "no_restart_before_authorization",
            "policy_after",
            "recorded_stage_absent",
            "recorded_stage_path",
            "residue_after",
            "target_after",
        }
        or re.fullmatch(
            r"/profile/state/extensions/\.openclaw-install-stage-[A-Za-z0-9]+",
            stage_path,
        )
        is None
        or allowed["recorded_stage_absent"] is not True
        or allowed["no_restart_before_authorization"]
        != {"passed": True, "ready_after": [], "restart_records": []}
        or allowed["target_after"]["digest"] != _PLUG01_FIXTURE_DIGESTS["allowed"]
        or allowed["target_after"]["entries"] != setup["fixtures"]["allowed"]["entries"]
        or allowed["target_after"]["path"] != setup["target"]["path"]
        or set(install) != {"install", "plugin", "valid"}
        or install["valid"] is not True
        or install["install"]["install_path"]
        != "/profile/state/extensions/aragorn-plug01"
        or install["install"]["source"] != "path"
        or install["install"]["source_path"] != "/sources/allowed-source"
        or install["install"]["version"] != "2.0.0"
        or not (
            _time(command["started_at"])
            <= _time(install["install"]["installed_at"])
            <= _time(command["completed_at"])
        )
        or install["plugin"]
        != {
            "id": "aragorn-plug01",
            "source": "/profile/state/extensions/aragorn-plug01/index.js",
            "status": "loaded",
            "version": "2.0.0",
        }
        or allowed["policy_after"]["count"] != 5
        or allowed["policy_after"]["count"] != len(allowed["policy_after"]["routes"])
        or allowed["policy_after"]["digest"]
        != "sha256:2b7a7ad0a96234d04b5e74c61c45797c2756860acdd48b1f79b4e9c2ec5ca03a"
        or allowed["policy_after"]["path"]
        != "/profile/state/plug01-policy-requests.jsonl"
        or allowed["policy_after"]["routes"][:3] != blocked["policy_after"]["routes"]
        or allowed["policy_after"]["routes"][3:]
        != [
            {
                "decision": "allow",
                "input_digest": (
                    "sha256:7856f35e00f291eaf5fe5d1f98b98947473dfdf4442432c2e83b1d3612a139b8"
                ),
                "route": "allowed-source",
                "source_path": "/sources/allowed-source",
            },
            {
                "decision": "allow",
                "input_digest": (
                    "sha256:c4bca7ee0bf610d43bc76b192e2368413389a0d2660c402f115fd93f307e82d6"
                ),
                "route": "allowed-installed-dependency-tree",
                "source_path": stage_path,
            },
        ]
        or allowed["residue_after"]
        != {
            "clean": True,
            "entries": [".openclaw-install-backups", "aragorn-plug01"],
            "residue": [],
            "root": "/profile/state/extensions",
        }
    ):
        raise AdmissionEvidenceError("PLUG-01 allowed replacement changed")

    post = evidence["post_restart"]
    if set(post) != {
        "activation",
        "final_config",
        "final_install",
        "final_policy",
        "final_residue",
        "final_target",
        "lifecycle",
        "link_after",
        "link_before",
        "restart_command",
        "restart_response",
        "status_before",
    }:
        raise AdmissionEvidenceError("PLUG-01 restart evidence changed")
    _verify_plug01_status(post["status_before"], [])
    if post["activation"]["poll_count"] != 1:
        raise AdmissionEvidenceError("PLUG-01 restart poll changed")
    _verify_plug01_status(
        post["activation"]["status"],
        [_plug01_skill_match()],
    )
    restart = post["restart_response"]
    restart_command = post["restart_command"]
    expected_restart = {
        "message": "safe restart requested; gateway will restart momentarily",
        "ok": True,
        "preflight": {
            "blockers": [],
            "counts": {
                "activeTasks": 0,
                "cronRuns": 0,
                "embeddedRuns": 0,
                "pendingReplies": 0,
                "queueSize": 0,
                "totalActive": 0,
            },
            "safe": True,
            "summary": "safe to restart now",
        },
        "restart": {
            "coalesced": False,
            "cooldownMsApplied": 0,
            "delayMs": 0,
            "emitHooksQueued": False,
            "mode": "emit",
            "ok": True,
            "pid": probe["gateway"]["shutdown"]["pid"],
            "reason": "gateway.restart.safe",
            "signal": "SIGUSR1",
        },
        "result": "scheduled",
    }
    lifecycle = post["lifecycle"]
    lifecycle_order = [
        lifecycle[name]
        for name in ("signal", "restarting", "shutdown", "restart_mode", "ready")
    ]
    if (
        restart != expected_restart
        or restart_command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "restart",
            "--safe",
            "--json",
        ]
        or restart_command["exit_code"] != 0
        or restart_command["signal"] is not None
        or restart_command["error"] is not None
        or restart_command["stdout_bytes"] != 0
        or restart_command["stdout_digest"] != _EMPTY_DIGEST
        or json.loads(restart_command["stderr_excerpt"]) != restart
        or _time(restart_command["started_at"]) > _time(restart_command["completed_at"])
        or _time(allowed["command"]["completed_at"])
        > _time(restart_command["started_at"])
        or _time(restart_command["started_at"]) > _time(lifecycle_order[0]["time"])
        or lifecycle["complete"] is not True
        or [item["message"] for item in lifecycle_order]
        != [
            "signal SIGUSR1 received",
            "received SIGUSR1; restarting",
            "shutdown completed cleanly in 76ms",
            "restart mode: in-process restart (OPENCLAW_NO_RESPAWN)",
            "gateway ready",
        ]
        or [item["offset"] for item in lifecycle_order]
        != sorted(item["offset"] for item in lifecycle_order)
        or any(
            left["offset"] >= right["offset"]
            for left, right in pairwise(lifecycle_order)
        )
        or any(
            _time(left["time"]) > _time(right["time"])
            for left, right in pairwise(lifecycle_order)
        )
        or _time(lifecycle_order[-1]["time"])
        > _time(post["activation"]["status"]["command"]["completed_at"])
        or post["final_config"] != allowed["config_after"]
        or post["final_install"] != allowed["install_after"]
        or post["final_policy"] != allowed["policy_after"]
        or post["final_residue"] != allowed["residue_after"]
        or post["final_target"] != allowed["target_after"]
    ):
        raise AdmissionEvidenceError("PLUG-01 explicit restart changed")

    expected_link = {
        "digest": (
            "sha256:1e0ffd518092758e31eb42fe6ee416599933e8fd97c6b9c02a6a95b1253b6a9c"
        ),
        "exists": True,
        "fixture": "allowed",
        "path": "/profile/state/plugin-skills/aragorn-plug01-skill",
        "realpath": (
            "/profile/state/extensions/aragorn-plug01/skills/aragorn-plug01-skill"
        ),
        "symlink_target": (
            "/profile/state/extensions/aragorn-plug01/skills/aragorn-plug01-skill"
        ),
    }
    log = probe["gateway_log"]
    if (
        post["link_before"] != setup["link"]
        or post["link_after"] != expected_link
        or log["ready_count"] != 2
        or log["restart_mode_count"] != 1
        or log["marker_records"][3:8] != lifecycle_order
        or probe["gateway"]["final_log"]["marker_records"][:8] != log["marker_records"]
        or probe["gateway"]["final_log"]["ready_count"] != 2
        or probe["gateway"]["final_log"]["restart_mode_count"] != 1
        or probe["gateway"]["shutdown"]["exit_code"] != 0
        or probe["gateway"]["shutdown"]["signal"] is not None
        or probe["gateway"]["shutdown"]["spawn_error"] is not None
        or _time(probe["recorded_at"])
        < _time(probe["gateway"]["final_log"]["marker_records"][-1]["time"])
    ):
        raise AdmissionEvidenceError("PLUG-01 replacement lifecycle changed")


def _verify_plug01_environment(
    activation: Mapping[str, Any],
    replacement: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> None:
    if (
        set(environment)
        != {
            "containers",
            "docker",
            "image",
            "isolation",
            "limitations",
            "os_profile_digest",
            "recorded_at",
            "runtime",
            "schema",
        }
        or canonical_digest(environment["docker"])
        != "sha256:1b1cd438cd8e830e2553942d965889f86a46c8cca95be3449be0fbed299f34f4"
        or environment["docker"]["assurance"]
        != "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"
        or environment["docker"]["context"]
        != {
            "endpoint": "unix:///Users/yousi/.colima/default/docker.sock",
            "name": "colima",
            "skip_tls_verify": False,
            "tls_material_count": 0,
        }
        or environment["docker"]["server"]["security_options"]
        != [
            "name=apparmor",
            "name=cgroupns",
            "name=seccomp,profile=builtin",
        ]
        or environment["image"]
        != {
            "id": (
                "sha256:242549cd46785b480c832479a730f4f2"
                "a20865d61ea2e404fdb2a5c3d3b73ecf"
            ),
            "index_digest": (
                "sha256:242549cd46785b480c832479a730f4f2"
                "a20865d61ea2e404fdb2a5c3d3b73ecf"
            ),
            "platform": {
                "architecture": "arm64",
                "os": "linux",
                "variant": "v8",
            },
            "platform_manifest_digest": _OPENCLAW_PLATFORM_MANIFEST,
            "reference": (
                "node@sha256:242549cd46785b480c832479a730f4f2"
                "a20865d61ea2e404fdb2a5c3d3b73ecf"
            ),
        }
        or environment["runtime"]
        != {
            "commit": _OPENCLAW_COMMIT,
            "name": "openclaw-contained",
            "source_tree_digest": _OPENCLAW_RUNTIME_TREE,
            "version": "2026.7.1",
            "volume": "aragorn-openclaw-2026-7-1-runtime-v2",
        }
    ):
        raise AdmissionEvidenceError("PLUG-01 environment identity changed")

    isolation = environment["isolation"]
    if (
        canonical_digest(isolation)
        != "sha256:3ad1885c1c6e058b07e376a831a749b8f0a7d2b6b38fc2bc5d08ac0c3741cf36"
        or set(isolation)
        != {
            "auto_remove",
            "binds",
            "cap_add",
            "cap_drop",
            "cgroupns_mode",
            "devices",
            "environment",
            "ipc_mode",
            "memory_bytes",
            "memory_swap_bytes",
            "nano_cpus",
            "network_mode",
            "no_new_privileges",
            "pids_limit",
            "port_bindings",
            "privileged",
            "read_only_rootfs",
            "restart_policy",
            "runtime",
            "tmpfs",
            "ulimits",
            "user",
            "working_dir",
        }
        or isolation["auto_remove"] is not False
        or isolation["binds"] != []
        or isolation["cap_add"] != []
        or isolation["cap_drop"] != ["ALL"]
        or isolation["cgroupns_mode"] != "private"
        or isolation["devices"] != []
        or isolation["ipc_mode"] != "private"
        or isolation["memory_bytes"] != 1_073_741_824
        or isolation["memory_swap_bytes"] != 1_073_741_824
        or isolation["nano_cpus"] != 1_000_000_000
        or isolation["network_mode"] != "none"
        or isolation["no_new_privileges"] is not True
        or isolation["pids_limit"] != 128
        or isolation["port_bindings"] != {}
        or isolation["privileged"] is not False
        or isolation["read_only_rootfs"] is not True
        or isolation["restart_policy"] != {"maximum_retry_count": 0, "name": "no"}
        or isolation["runtime"] != "runc"
        or isolation["user"] != "1000:1000"
        or isolation["working_dir"] != "/profile/workspace"
        or isolation["ulimits"] != [{"hard": 256, "name": "nofile", "soft": 256}]
        or isolation["tmpfs"]
        != {
            "/profile/home": (
                "rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=1000,gid=1000"
            ),
            "/profile/workspace": (
                "rw,nosuid,nodev,noexec,size=32m,mode=0700,uid=1000,gid=1000"
            ),
            "/tmp": "rw,nosuid,nodev,noexec,size=256m,mode=1777",
        }
        or isolation["environment"]["OPENCLAW_NO_RESPAWN"] != "1"
        or isolation["environment"]["npm_config_offline"] != "true"
    ):
        raise AdmissionEvidenceError("PLUG-01 isolation changed")

    specs = [
        (
            "activation",
            "setup",
            "setup",
            "aragorn-openclaw-contained-plug01-activate-setup-v3",
            "activate",
            False,
            10_765,
            activation["consumed_setup"]["binding"]["digest"],
            "aragorn/openclaw-contained-plug01-setup-evidence/v1",
            activation["consumed_setup"]["binding"]["recorded_at"],
        ),
        (
            "activation",
            "evaluation",
            "activate",
            "aragorn-openclaw-contained-plug01-activate-v3",
            "activate",
            True,
            24_955,
            _PLUG01_ACTIVATION_DIGEST,
            _PLUG01_ACTIVATION_SCHEMA,
            activation["recorded_at"],
        ),
        (
            "replacement",
            "setup",
            "setup",
            "aragorn-openclaw-contained-plug01-replace-setup-v3",
            "replace",
            False,
            10_765,
            replacement["consumed_setup"]["binding"]["digest"],
            "aragorn/openclaw-contained-plug01-setup-evidence/v1",
            replacement["consumed_setup"]["binding"]["recorded_at"],
        ),
        (
            "replacement",
            "evaluation",
            "replace",
            "aragorn-openclaw-contained-plug01-replace-v3",
            "replace",
            False,
            36_346,
            _PLUG01_REPLACEMENT_DIGEST,
            _PLUG01_REPLACEMENT_SCHEMA,
            replacement["recorded_at"],
        ),
    ]
    containers = environment["containers"]
    if len(containers) != len(specs) or len({item["id"] for item in containers}) != len(
        specs
    ):
        raise AdmissionEvidenceError("PLUG-01 container count changed")
    common_mounts = {
        "/probe": (
            "aragorn-openclaw-2026-7-1-contained-plug01-probe-v3",
            True,
        ),
        "/runtime": ("aragorn-openclaw-2026-7-1-runtime-v2", True),
        "/sources": (
            "aragorn-openclaw-2026-7-1-contained-plug01-sources-v2",
            True,
        ),
    }
    for container, spec in zip(containers, specs, strict=True):
        (
            profile,
            role,
            mode,
            name,
            volume_stem,
            extensions_read_only,
            output_bytes,
            output_digest,
            output_schema,
            output_time,
        ) = spec
        if (
            set(container)
            != {
                "command",
                "created_at",
                "id",
                "mode",
                "mounts",
                "name",
                "output",
                "profile",
                "role",
                "state",
            }
            or (container["profile"], container["role"], container["mode"])
            != (profile, role, mode)
            or container["name"] != name
            or container["command"]
            != ["/usr/local/bin/node", "/probe/plug01-probe.mjs", mode]
            or container["output"]
            != {
                "bytes": output_bytes,
                "digest": output_digest,
                "recorded_at": output_time,
                "schema": output_schema,
            }
        ):
            raise AdmissionEvidenceError("PLUG-01 container identity changed")
        state = container["state"]
        if (
            state["dead"] is not False
            or state["error"] != ""
            or state["exit_code"] != 0
            or state["oom_killed"] is not False
            or state["paused"] is not False
            or state["restart_count"] != 0
            or state["restarting"] is not False
            or state["running"] is not False
            or state["status"] != "exited"
            or not (
                _time(container["created_at"])
                <= _time(state["started_at"])
                <= _time(output_time)
                <= _time(state["finished_at"])
            )
        ):
            raise AdmissionEvidenceError("PLUG-01 container state changed")
        mounts = {item["destination"]: item for item in container["mounts"]}
        if (
            len(container["mounts"]) != 5
            or set(mounts)
            != {
                "/probe",
                "/profile/state",
                "/profile/state/extensions",
                "/runtime",
                "/sources",
            }
            or any(
                mounts[destination]
                != {
                    "destination": destination,
                    "read_only": read_only,
                    "source": source,
                    "type": "volume",
                }
                for destination, (source, read_only) in common_mounts.items()
            )
            or mounts["/profile/state"]
            != {
                "destination": "/profile/state",
                "read_only": False,
                "source": (
                    f"aragorn-openclaw-2026-7-1-contained-plug01-{volume_stem}-state-v3"
                ),
                "type": "volume",
            }
            or mounts["/profile/state/extensions"]
            != {
                "destination": "/profile/state/extensions",
                "read_only": extensions_read_only,
                "source": (
                    "aragorn-openclaw-2026-7-1-contained-plug01-"
                    f"{volume_stem}-extensions-v3"
                ),
                "type": "volume",
            }
        ):
            raise AdmissionEvidenceError("PLUG-01 mount isolation changed")
    if (
        _time(containers[0]["state"]["finished_at"])
        > _time(containers[1]["state"]["started_at"])
        or _time(containers[2]["state"]["finished_at"])
        > _time(containers[3]["state"]["started_at"])
        or _time(environment["recorded_at"])
        < max(_time(item["state"]["finished_at"]) for item in containers)
    ):
        raise AdmissionEvidenceError("PLUG-01 container lineage is not causal")

    profile = {
        "image": environment["image"],
        "isolation": isolation,
        "mounts": [{"id": item["id"], "mounts": item["mounts"]} for item in containers],
        "server": environment["docker"]["server"],
    }
    if environment["os_profile_digest"] != canonical_digest(profile) or environment[
        "limitations"
    ] != [
        "CONTAINER_EXIT_DOES_NOT_ESTABLISH_CROSS_HOST_REPRODUCIBILITY",
        "DOCKER_CONTROL_PLANE_SELF_REPORTED",
        "ENGINE_CONTAINER_AND_HOST_NOT_INDEPENDENTLY_ATTESTED",
        "PLATFORM_MANIFEST_DIGEST_RETAINED_NOT_INDEPENDENTLY_REDERIVED",
        "RUNTIME_VOLUME_TREE_DIGEST_RETAINED_NOT_INDEPENDENTLY_REDERIVED",
    ]:
        raise AdmissionEvidenceError("PLUG-01 environment binding changed")


def _verify_update_reload_coverage_v2(
    receipt: Mapping[str, Any],
    coverage: Mapping[str, Any],
    *,
    activation: Mapping[str, Any],
    replacement: Mapping[str, Any],
    environment: Mapping[str, Any],
    v1_receipt: Mapping[str, Any],
    evidence_cas: CAS,
    route_inventory: Mapping[str, Any],
) -> None:
    if (
        set(coverage)
        != {
            "assurance",
            "decision",
            "partial_observations",
            "recorded_at",
            "route_inventory_canonical_digest",
            "routes",
            "schema",
            "source_evidence_digests",
            "source_receipt_digests",
        }
        or coverage["assurance"]
        != ("SEMANTICALLY_VERIFIED_CUMULATIVE_PARTIAL_COVERAGE_NOT_INSTALLER_AUTHORITY")
        or coverage["decision"]
        != {"status": "NOT_TESTED", "installer_work_eligible": False}
        or coverage["recorded_at"] != receipt["recorded_at"]
        or coverage["route_inventory_canonical_digest"]
        != canonical_digest(route_inventory)
        or coverage["route_inventory_canonical_digest"]
        != _UPDATE_RELOAD_INVENTORY_DIGEST
        or coverage["source_evidence_digests"] != _PLUG01_EVIDENCE_DIGESTS
        or coverage["source_receipt_digests"] != [_UPDATE_RELOAD_V1_RECEIPT_DIGEST]
    ):
        raise AdmissionEvidenceError("PLUG-01 coverage envelope changed")

    v1_coverage = _read_exact(
        evidence_cas,
        _UPDATE_RELOAD_COVERAGE_DIGEST,
        _UPDATE_RELOAD_COVERAGE_SCHEMA,
    )
    if coverage["partial_observations"] != v1_coverage["partial_observations"] or _time(
        coverage["recorded_at"]
    ) < max(
        _time(v1_receipt["recorded_at"]),
        _time(activation["recorded_at"]),
        _time(replacement["recorded_at"]),
        _time(environment["recorded_at"]),
    ):
        raise AdmissionEvidenceError("PLUG-01 coverage provenance changed")

    expected_routes = []
    for prior in v1_coverage["routes"]:
        expected = {
            "id": prior["id"],
            "source_evidence_digests": [],
            "source_receipt_digests": prior["source_receipt_digests"],
            "status": prior["status"],
        }
        if prior["id"] in _PLUG01_ROUTE_SOURCES:
            if prior["status"] != "NOT_TESTED":
                raise AdmissionEvidenceError("PLUG-01 route was not additive")
            expected["source_evidence_digests"] = _PLUG01_ROUTE_SOURCES[prior["id"]]
            expected["status"] = "PASS"
        expected_routes.append(expected)
    if coverage["routes"] != expected_routes:
        raise AdmissionEvidenceError("PLUG-01 coverage was not derived exactly")
    passes = [item["id"] for item in expected_routes if item["status"] == "PASS"]
    if (
        sum("/update/" in route for route in passes) != 3
        or sum("/reload/" in route for route in passes) != 6
        or next(
            item
            for item in expected_routes
            if item["id"] == "ADM-02/update/plugin-package-skill-replacement"
        )["status"]
        != "NOT_TESTED"
    ):
        raise AdmissionEvidenceError("PLUG-01 coverage boundary changed")

    implementation_digest = (
        "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    )
    configuration = {
        "route_inventory_canonical_digest": _UPDATE_RELOAD_INVENTORY_DIGEST,
        "source_evidence_digests": _PLUG01_EVIDENCE_DIGESTS,
        "source_receipt_digests": [_UPDATE_RELOAD_V1_RECEIPT_DIGEST],
    }
    expected_runtime = {
        "commit": environment["runtime"]["commit"],
        "name": environment["runtime"]["name"],
        "repository_url": "https://github.com/openclaw/openclaw",
        "source_tree_digest": environment["runtime"]["source_tree_digest"],
        "version": environment["runtime"]["version"],
    }
    if v1_receipt["bindings"]["runtime"] != expected_runtime:
        raise AdmissionEvidenceError("PLUG-01 source runtime binding changed")
    expected_bindings = {
        "runtime": expected_runtime,
        "adapter": {
            "name": "openclaw-update-reload-route-coverage-v2",
            "implementation_digest": implementation_digest,
            "configuration_digest": canonical_digest(configuration),
        },
        "environment": {
            "worker_digest": environment["image"]["platform_manifest_digest"],
            "os_profile_digest": environment["os_profile_digest"],
        },
        "aragorn": {
            "implementation_digest": canonical_digest(
                {
                    "coverage_verifier_digest": implementation_digest,
                    "source_evidence_digests": _PLUG01_EVIDENCE_DIGESTS,
                    "source_receipt_digests": [_UPDATE_RELOAD_V1_RECEIPT_DIGEST],
                }
            ),
            "policy_digest": v1_receipt["bindings"]["aragorn"]["policy_digest"],
        },
    }
    if receipt["bindings"] != expected_bindings:
        raise AdmissionEvidenceError("PLUG-01 coverage bindings changed")
