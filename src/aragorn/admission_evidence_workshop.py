"""Semantic verification for retained OpenClaw workshop bypass evidence."""

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
    _UPDATE_RELOAD_INVENTORY_DIGEST,
    AdmissionEvidenceError,
    _canonical_bytes,
    _read_exact,
    _time,
    _verify_successful_config_command,
)
from .admission_evidence_plug01 import (
    verify_openclaw_update_reload_coverage_v2,
)
from .admission_routes import validate_openclaw_2026_7_1_route_inventory
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest

_WORKSHOP_SCHEMA = "aragorn/openclaw-contained-workshop-bypass-evidence/v1"
_WORKSHOP_ENV_SCHEMA = (
    "aragorn/openclaw-contained-workshop-bypass-environment-evidence/v1"
)
_COVERAGE_V2_SCHEMA = "aragorn/openclaw-update-reload-route-coverage-evidence/v2"
_COVERAGE_V3_SCHEMA = "aragorn/openclaw-update-reload-route-coverage-evidence/v3"
_CONFORMANCE_SCHEMA = "aragorn/admission-conformance-result/v1"
_WORKSHOP_ROUTE = "ADM-02/update/workshop-proposal-apply"
_WORKSHOP_REASON = "WORKSHOP_APPLY_BYPASSES_INSTALL_POLICY"
_WORKSHOP_EVIDENCE_DIGEST = (
    "sha256:a1ce5f52182d72426e967587154e26976cf7e54684cff82cf22cdfae12364206"
)
_WORKSHOP_ENV_DIGEST = (
    "sha256:f3a90a284054acc2c27ef412736bf259c7c9a99a50ca0f37cb65d9124ac33e89"
)
_COVERAGE_V3_DIGEST = (
    "sha256:b4ad2979a02d33370fae0bef8af5b142d7603fcbef165ef0609c73a3a72b3789"
)
_COVERAGE_V2_DIGEST = (
    "sha256:df34ef52fd06728b2a7633e5f2c19cb463907c5b97cba18a5056485596291600"
)
_RECEIPT_V2_DIGEST = (
    "sha256:dbd3109be3eb5bb880dc1a07a84c32957c52430ff36316cf61cc87cc39350f37"
)
_WORKSHOP_SETUP_DIGEST = (
    "sha256:e11cd4f4e1e7db2ed5a013e8ea4e2eaea7a759626ae5727a11a1a7ce74472316"
)
_WORKSHOP_ADAPTER_DIGEST = (
    "sha256:f5f276f67f27d2b4d6cde9632eb6701af79874ea5b99c3dbc6b4fa8323d6d42f"
)
_WORKSHOP_CONFIGURATION_DIGEST = (
    "sha256:108f9a4487ce0f3b82005c9f076d6ddbe506a9d4b601140d8fe967d2c5968419"
)
_WORKSHOP_SOURCES = sorted((_WORKSHOP_EVIDENCE_DIGEST, _WORKSHOP_ENV_DIGEST))
_TARGET_PATH = "/profile/workspace/skills/aragorn-plug01-workshop/SKILL.md"
_PROPOSAL_ID = "aragorn-plug01-workshop-20260728-2508d1beed"
_LIMITATIONS = [
    "CONTAINER_EXIT_DOES_NOT_ESTABLISH_CROSS_HOST_REPRODUCIBILITY",
    "DOCKER_CONTROL_PLANE_SELF_REPORTED",
    "ENGINE_CONTAINER_AND_HOST_NOT_INDEPENDENTLY_ATTESTED",
    "PLATFORM_MANIFEST_DIGEST_RETAINED_NOT_INDEPENDENTLY_REDERIVED",
    "RUNTIME_VOLUME_TREE_DIGEST_RETAINED_NOT_INDEPENDENTLY_REDERIVED",
]


def verify_openclaw_update_reload_coverage_v3(
    document: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> None:
    """Verify the workshop policy bypass and retain its route failure."""

    try:
        _verify_receipt_shape(document)
        workshop = _read_exact(
            evidence_cas,
            _WORKSHOP_EVIDENCE_DIGEST,
            _WORKSHOP_SCHEMA,
        )
        environment = _read_exact(
            evidence_cas,
            _WORKSHOP_ENV_DIGEST,
            _WORKSHOP_ENV_SCHEMA,
        )
        coverage = _read_exact(
            evidence_cas,
            _COVERAGE_V3_DIGEST,
            _COVERAGE_V3_SCHEMA,
        )
        prior_receipt = _read_exact(
            evidence_cas,
            _RECEIPT_V2_DIGEST,
            _CONFORMANCE_SCHEMA,
        )
        validate_openclaw_2026_7_1_route_inventory(
            route_inventory,
            runtime_candidates,
        )
        verify_openclaw_update_reload_coverage_v2(
            prior_receipt,
            evidence_cas=evidence_cas,
            route_inventory=route_inventory,
            runtime_candidates=runtime_candidates,
        )
        _verify_formal_claims(document, prior_receipt)
        _verify_workshop_bypass(workshop)
        _verify_workshop_environment(workshop, environment)
        _verify_update_reload_coverage_v3(
            document,
            coverage,
            workshop=workshop,
            environment=environment,
            prior_receipt=prior_receipt,
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
            f"invalid retained workshop coverage: {exc}"
        ) from exc


def _verify_receipt_shape(document: Mapping[str, Any]) -> None:
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
        or document["schema"] != _CONFORMANCE_SCHEMA
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
        or validate_admission_conformance(document) != "FAIL"
        or document["decision"] != {"status": "FAIL", "installer_work_eligible": False}
    ):
        raise AdmissionEvidenceError("workshop FAIL receipt shape changed")


def _verify_formal_claims(
    receipt: Mapping[str, Any],
    prior_receipt: Mapping[str, Any],
) -> None:
    actual_items = [
        (f"{item['id']}/{scenario['id']}", item, scenario)
        for item in receipt["properties"]
        for scenario in item["scenarios"]
    ]
    prior_items = [
        (f"{item['id']}/{scenario['id']}", item, scenario)
        for item in prior_receipt["properties"]
        for scenario in item["scenarios"]
    ]
    if [key for key, _, _ in actual_items] != [key for key, _, _ in prior_items]:
        raise AdmissionEvidenceError("workshop formal claim order changed")

    for (key, actual_property, actual), (_, prior_property, prior) in zip(
        actual_items,
        prior_items,
        strict=True,
    ):
        expected = dict(prior)
        if key == "ADM-02/update":
            expected = {
                "evidence_digests": [_COVERAGE_V3_DIGEST],
                "id": "update",
                "reason_codes": [_WORKSHOP_REASON],
                "status": "FAIL",
            }
        elif key == "ADM-02/reload":
            expected = {
                "evidence_digests": [_COVERAGE_V3_DIGEST],
                "id": "reload",
                "reason_codes": ["RELOAD_ROUTE_COVERAGE_INCOMPLETE"],
                "status": "NOT_TESTED",
            }
        if actual != expected:
            raise AdmissionEvidenceError(f"{key} formal workshop claim changed")
        expected_property_status = (
            "FAIL" if actual_property["id"] == "ADM-02" else prior_property["status"]
        )
        if actual_property["status"] != expected_property_status:
            raise AdmissionEvidenceError("workshop property status changed")


def _verify_workshop_bypass(probe: Mapping[str, Any]) -> None:  # noqa: PLR0915
    if (
        set(probe)
        != {
            "adapter",
            "assurance",
            "consumed_setup",
            "decision",
            "draft",
            "gateway",
            "recorded_at",
            "runtime",
            "scenario",
            "schema",
        }
        or probe["schema"] != _WORKSHOP_SCHEMA
        or probe["assurance"]
        != "SELF_REPORTED_CONTAINED_RUNTIME_NOT_INDEPENDENTLY_ATTESTED"
        or probe["decision"] != {"status": "FAIL", "installer_work_eligible": False}
    ):
        raise AdmissionEvidenceError("workshop evidence envelope changed")

    setup_binding = probe["consumed_setup"]
    setup = setup_binding["document"]
    setup_raw = _canonical_bytes(setup) + b"\n"
    if (
        set(setup_binding)
        != {
            "digest",
            "document",
            "path",
            "policy_digest",
            "recorded_at",
            "schema",
            "target_digest",
        }
        or "sha256:" + hashlib.sha256(setup_raw).hexdigest() != _WORKSHOP_SETUP_DIGEST
        or setup_binding["digest"] != _WORKSHOP_SETUP_DIGEST
        or setup_binding["path"] != "/profile/state/plug01-setup.json"
        or setup_binding["policy_digest"] != setup["setup"]["policy"]["digest"]
        or setup_binding["recorded_at"] != setup["recorded_at"]
        or setup_binding["schema"]
        != "aragorn/openclaw-contained-plug01-setup-evidence/v1"
        or setup_binding["schema"] != setup["schema"]
        or setup_binding["target_digest"] != setup["setup"]["target"]["digest"]
        or setup["decision"]
        != {"status": "NOT_TESTED", "installer_work_eligible": False}
        or setup["setup"]["status"] != "PASS"
    ):
        raise AdmissionEvidenceError("workshop setup provenance changed")

    adapter = probe["adapter"]
    setup_configuration = setup["adapter"]["configuration"]
    expected_configuration = json.loads(json.dumps(setup_configuration))
    expected_configuration["agents"]["defaults"]["skills"].append(
        "aragorn-plug01-workshop"
    )
    expected_configuration["agents"]["list"][0]["skills"].append(
        "aragorn-plug01-workshop"
    )
    if (
        set(adapter)
        != {
            "configuration",
            "configuration_digest",
            "implementation_digest",
            "name",
        }
        or adapter["name"] != "openclaw-contained-workshop-bypass"
        or adapter["configuration"] != expected_configuration
        or adapter["configuration_digest"] != canonical_digest(adapter["configuration"])
        or adapter["configuration_digest"] != _WORKSHOP_CONFIGURATION_DIGEST
        or adapter["implementation_digest"] != _WORKSHOP_ADAPTER_DIGEST
    ):
        raise AdmissionEvidenceError("workshop producer identity changed")

    runtime = probe["runtime"]
    _verify_successful_config_command(
        runtime["version_command"],
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
        or runtime["version_command"]["stdout_bytes"]
        != _MODEL_ACTIVATION_VERSION_STDOUT_BYTES
        or runtime["version_command"]["stdout_digest"]
        != "sha256:9e98975ff3973bcd88f224e1820a177c3c881f7a46b51b7dc5ec5d050f72607f"
    ):
        raise AdmissionEvidenceError("workshop runtime identity changed")

    draft = probe["draft"]
    draft_raw = draft["text"].encode("utf-8")
    if (
        set(draft) != {"bytes", "digest", "mode", "path", "text"}
        or draft["bytes"] != len(draft_raw)
        or draft["digest"] != "sha256:" + hashlib.sha256(draft_raw).hexdigest()
        or draft["digest"]
        != "sha256:1a02b300bd83832000d246b6e161db25be59580657a24e064f22562af24978e3"
        or draft["mode"] != "444"
        or draft["path"] != "/profile/workspace/PROPOSAL.md"
        or draft["text"]
        != (
            "# Aragorn PLUG-01 workshop fixture\n\n"
            "This inert fixture performs no actions.\n"
        )
    ):
        raise AdmissionEvidenceError("workshop draft changed")

    scenario = probe["scenario"]
    if (
        set(scenario) != {"evidence", "id", "reason_codes", "status"}
        or scenario["id"] != _WORKSHOP_ROUTE
        or scenario["reason_codes"] != [_WORKSHOP_REASON]
        or scenario["status"] != "FAIL"
    ):
        raise AdmissionEvidenceError("workshop route claim changed")
    evidence = scenario["evidence"]
    if set(evidence) != {
        "apply",
        "config_after",
        "config_before",
        "control",
        "policy_after_apply",
        "policy_after_control",
        "policy_after_proposal",
        "policy_before",
        "process_after",
        "process_before",
        "proposal",
        "status_after",
        "target_absent_after_proposal",
        "target_absent_before",
        "target_after",
    }:
        raise AdmissionEvidenceError("workshop producer evidence changed")

    _verify_workshop_config(
        evidence["config_before"],
        adapter["configuration"],
    )
    _verify_workshop_config(
        evidence["config_after"],
        adapter["configuration"],
    )
    if evidence["config_before"] != evidence["config_after"]:
        raise AdmissionEvidenceError("workshop apply changed runtime configuration")

    policy_before = _verify_policy_snapshot(evidence["policy_before"])
    policy_after_control = _verify_policy_snapshot(evidence["policy_after_control"])
    policy_after_proposal = _verify_policy_snapshot(evidence["policy_after_proposal"])
    policy_after_apply = _verify_policy_snapshot(evidence["policy_after_apply"])
    setup_policy = setup["setup"]["policy"]
    prior_routes = [
        {
            "decision": record["decision"],
            "input_digest": record["input_digest"],
            "route": record["route"],
            "source_path": record["source"]["path"],
        }
        for record in policy_before
    ]
    if (
        setup_policy
        != {
            "count": len(policy_before),
            "digest": evidence["policy_before"]["digest"],
            "path": evidence["policy_before"]["path"],
            "routes": prior_routes,
        }
        or policy_after_control[: len(policy_before)] != policy_before
        or len(policy_after_control) != len(policy_before) + 1
        or policy_after_proposal != policy_after_control
        or policy_after_apply != policy_after_control
    ):
        raise AdmissionEvidenceError("workshop policy lineage changed")

    control = evidence["control"]
    _verify_blocked_control(control["command"])
    control_record = policy_after_control[-1]
    if (
        set(control) != {"command", "installed", "source", "target"}
        or control["installed"] is not False
        or control["target"] != "/profile/state/skills/aragorn-policy-control"
        or control_record["decision"] != "block"
        or control_record["route"] != "unrecognized"
        or control_record["request"]
        != {
            "openclawVersion": "2026.7.1",
            "origin": {
                "spec": "/profile/workspace/policy-control",
                "type": "path",
            },
            "protocolVersion": 1,
            "request": {
                "kind": "skill-install",
                "mode": "install",
                "requestedSpecifier": "/profile/workspace/policy-control",
            },
            "skill": {"installId": "path"},
            "source": {
                "authority": "user",
                "kind": "local-path",
                "mutable": True,
                "network": False,
            },
            "sourcePath": "/profile/workspace/policy-control",
            "sourcePathKind": "directory",
            "targetName": "aragorn-policy-control",
            "targetType": "skill",
        }
        or _time(control["command"]["started_at"])
        > _time(control_record["recorded_at"])
        or _time(control_record["recorded_at"])
        > _time(control["command"]["completed_at"])
    ):
        raise AdmissionEvidenceError("workshop install-policy control changed")
    _verify_file(
        control["source"],
        path="/profile/workspace/policy-control/SKILL.md",
        mode="444",
        digest="sha256:ae5a395f9404e2a354e0640ecad137c112c91cdc9b177cd5a5b33fd5360ef25a",
    )

    proposal = evidence["proposal"]
    _verify_json_command(
        proposal["command"],
        [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "skills",
            "workshop",
            "--agent",
            "main",
            "propose-create",
            "--name",
            "aragorn-plug01-workshop",
            "--description",
            "Inert PLUG-01 workshop fixture",
            "--proposal",
            "/profile/workspace/PROPOSAL.md",
            "--json",
        ],
        proposal["response"],
        "sha256:62b959b93d03878b3f9d51d1b87c898f08351378f0102ec1ba7ebef28c03b7e1",
    )
    apply = evidence["apply"]
    _verify_json_command(
        apply["command"],
        [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            "skills.proposals.apply",
            "--json",
            "--timeout",
            "5000",
            "--params",
            f'{{"agentId":"main","proposalId":"{_PROPOSAL_ID}"}}',
        ],
        apply["response"],
        "sha256:218a008d8aec2a07a3eb0da20b1ef3b597e85f97f1b2ac6bd0815fa1f0d80f76",
    )
    _verify_workshop_records(proposal["response"], apply["response"])

    absent = {
        "directory_absent": True,
        "file_absent": True,
        "path": _TARGET_PATH,
    }
    if (
        evidence["target_absent_before"] != absent
        or evidence["target_absent_after_proposal"] != absent
    ):
        raise AdmissionEvidenceError("workshop proposal wrote before apply")
    _verify_file(
        evidence["target_after"],
        path=_TARGET_PATH,
        mode="600",
        digest="sha256:9e9679c366c749ebdea532722837946014514e38f79a310b34a2df43be874148",
    )

    status = evidence["status_after"]
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
    if (
        status["command"]["stdout_digest"]
        != "sha256:a47de0acc4685b31847dfe049d6bca81a84d45ea312659731e8d4d50543ae4c8"
        or status["matches"]
        != [
            {
                "blocked_by_agent_filter": False,
                "command_visible": True,
                "disabled": False,
                "eligible": True,
                "file_path": _TARGET_PATH,
                "model_visible": True,
                "name": "aragorn-plug01-workshop",
                "source": "openclaw-workspace",
                "user_invocable": True,
            }
        ]
        or evidence["process_before"] != evidence["process_after"]
        or evidence["process_before"]
        != {"alive": True, "pid": 20, "system_info_pid": 20}
    ):
        raise AdmissionEvidenceError("workshop activation result changed")

    _verify_workshop_gateway(probe["gateway"], status["command"])
    commands = [
        runtime["version_command"],
        control["command"],
        proposal["command"],
        apply["command"],
        status["command"],
    ]
    if (
        any(
            _time(left["completed_at"]) > _time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or _time(setup_binding["recorded_at"])
        > _time(runtime["version_command"]["started_at"])
        or _time(status["command"]["completed_at"]) > _time(probe["recorded_at"])
    ):
        raise AdmissionEvidenceError("workshop producer timeline changed")


def _verify_workshop_config(
    snapshot: Mapping[str, Any],
    expected_configuration: Mapping[str, Any],
) -> None:
    document = dict(snapshot["document"])
    meta = document.pop("meta")
    if (
        set(snapshot) != {"core_digest", "digest", "document", "mode", "path", "size"}
        or document != expected_configuration
        or snapshot["core_digest"] != canonical_digest(document)
        or snapshot["core_digest"] != _WORKSHOP_CONFIGURATION_DIGEST
        or snapshot["digest"]
        != "sha256:bd1105fdd809b4aff16d68ee8f45292b104c78af25f82590f9932bc099b324bb"
        or snapshot["mode"] != "600"
        or snapshot["path"] != "/profile/state/openclaw.json"
        or snapshot["size"] != 797
        or set(meta) != {"lastTouchedAt", "lastTouchedVersion"}
        or meta["lastTouchedVersion"] != "2026.7.1"
    ):
        raise AdmissionEvidenceError("workshop configuration snapshot changed")


def _verify_policy_snapshot(snapshot: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if set(snapshot) != {"count", "digest", "path", "records"}:
        raise AdmissionEvidenceError("workshop policy snapshot shape changed")
    records = snapshot["records"]
    raw = b"".join(_canonical_bytes(record) + b"\n" for record in records)
    if (
        snapshot["count"] != len(records)
        or snapshot["digest"] != "sha256:" + hashlib.sha256(raw).hexdigest()
        or snapshot["path"] != "/profile/state/plug01-policy-requests.jsonl"
        or any(
            set(record)
            != {
                "decision",
                "input_bytes",
                "input_digest",
                "oversized",
                "parse_error",
                "protocol_version",
                "recorded_at",
                "request",
                "route",
                "source",
            }
            or record["decision"] not in {"allow", "block"}
            or not isinstance(record["input_bytes"], int)
            or record["input_bytes"] <= 0
            or re.fullmatch(r"sha256:[0-9a-f]{64}", record["input_digest"]) is None
            or record["oversized"] is not False
            or record["parse_error"] is not None
            or record["protocol_version"] != 1
            for record in records
        )
    ):
        raise AdmissionEvidenceError("workshop policy snapshot changed")
    return records


def _verify_blocked_control(command: Mapping[str, Any]) -> None:
    if (
        set(command)
        != {
            "argv",
            "completed_at",
            "error",
            "exit_code",
            "pid",
            "signal",
            "started_at",
            "stderr_bytes",
            "stderr_digest",
            "stderr_excerpt",
            "stdout_bytes",
            "stdout_digest",
            "stdout_excerpt",
        }
        or command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "skills",
            "install",
            "/profile/workspace/policy-control",
            "--as",
            "aragorn-policy-control",
            "--global",
        ]
        or command["exit_code"] != 1
        or command["signal"] is not None
        or command["error"] is not None
        or not isinstance(command["pid"], int)
        or command["pid"] <= 1
        or command["stderr_bytes"] != 74
        or command["stderr_digest"]
        != "sha256:380b6c39cd7829bc3c293c656d296046107d4bd093864a9b366ab670656800d1"
        or command["stderr_excerpt"]
        != "blocked by install policy: Aragorn PLUG-01 rejected an unexpected request\n"
        or command["stdout_bytes"] != 210
        or command["stdout_digest"]
        != "sha256:d3596999a11f200911f4ed37557e7fffdd20b1b1892e65bed8ec4af78e14902c"
        or _time(command["started_at"]) > _time(command["completed_at"])
    ):
        raise AdmissionEvidenceError("workshop blocked control command changed")


def _verify_json_command(
    command: Mapping[str, Any],
    argv: list[str],
    response: Mapping[str, Any],
    digest: str,
) -> None:
    _verify_successful_config_command(command, argv)
    stdout = command["stdout_excerpt"].encode("utf-8")
    if (
        command["stdout_bytes"] != len(stdout)
        or command["stdout_digest"] != "sha256:" + hashlib.sha256(stdout).hexdigest()
        or command["stdout_digest"] != digest
        or json.loads(command["stdout_excerpt"]) != response
    ):
        raise AdmissionEvidenceError("workshop JSON command output changed")


def _verify_workshop_records(
    proposal: Mapping[str, Any],
    apply: Mapping[str, Any],
) -> None:
    pending = proposal["record"]
    applied = apply["record"]
    expected_target = {
        "skillDir": "/profile/workspace/skills/aragorn-plug01-workshop",
        "skillFile": _TARGET_PATH,
        "skillKey": "aragorn-plug01-workshop",
        "skillName": "aragorn-plug01-workshop",
        "source": "openclaw-workspace",
    }
    shared = {
        "createdAt",
        "createdBy",
        "description",
        "draftFile",
        "draftHash",
        "id",
        "kind",
        "proposedVersion",
        "schema",
        "target",
        "title",
    }
    if (
        pending["id"] != _PROPOSAL_ID
        or pending["schema"] != "openclaw.skill-workshop.proposal.v1"
        or pending["kind"] != "create"
        or pending["status"] != "pending"
        or pending["target"] != expected_target
        or pending["scan"]
        != {
            "critical": 0,
            "findings": [],
            "info": 0,
            "scannedAt": pending["createdAt"],
            "state": "clean",
            "warn": 0,
        }
        or {key: pending[key] for key in shared}
        != {key: applied[key] for key in shared}
        or applied["status"] != "applied"
        or applied["target"] != expected_target
        or applied["scan"]["state"] != "clean"
        or any(applied["scan"][key] != 0 for key in ("critical", "info", "warn"))
        or applied["scan"]["findings"] != []
        or apply["targetSkillFile"] != _TARGET_PATH
        or _time(pending["createdAt"]) > _time(applied["appliedAt"])
    ):
        raise AdmissionEvidenceError("workshop proposal/apply record changed")


def _verify_file(
    document: Mapping[str, Any],
    *,
    path: str,
    mode: str,
    digest: str,
) -> None:
    raw = document["text"].encode("utf-8")
    if (
        set(document) != {"bytes", "digest", "mode", "path", "text"}
        or document["bytes"] != len(raw)
        or document["digest"] != "sha256:" + hashlib.sha256(raw).hexdigest()
        or document["digest"] != digest
        or document["mode"] != mode
        or document["path"] != path
    ):
        raise AdmissionEvidenceError("workshop retained file changed")


def _verify_workshop_gateway(
    gateway: Mapping[str, Any],
    status_command: Mapping[str, Any],
) -> None:
    shutdown = gateway["shutdown"]
    stdout = shutdown["stdout"]["excerpt"].encode("utf-8")
    final_log = gateway["final_log"]
    if (
        set(gateway) != {"final_log", "shutdown"}
        or shutdown["exit_code"] != 0
        or shutdown["pid"] != 20
        or shutdown["signal"] is not None
        or shutdown["spawn_error"] is not None
        or shutdown["stderr"]
        != {
            "bytes": 0,
            "digest": _EMPTY_DIGEST,
            "excerpt": "",
            "retained_bytes": 0,
            "truncated": False,
        }
        or shutdown["stdout"]["bytes"] != len(stdout)
        or shutdown["stdout"]["retained_bytes"] != len(stdout)
        or shutdown["stdout"]["truncated"] is not False
        or shutdown["stdout"]["digest"]
        != "sha256:" + hashlib.sha256(stdout).hexdigest()
        or shutdown["stdout"]["digest"]
        != "sha256:c44ca9b88ff8f6f0592ae94318fd2e05e239e357c1ec3abfff6d9697c97afed3"
        or final_log["ready_count"] != 1
        or final_log["restart_records"] != []
        or len(final_log["shutdown_records"]) != 1
        or final_log["shutdown_records"][0]["message"]
        != "shutdown completed cleanly in 13ms"
        or _time(status_command["completed_at"])
        > _time(final_log["shutdown_records"][0]["time"])
    ):
        raise AdmissionEvidenceError("workshop gateway lifecycle changed")


def _verify_workshop_environment(
    workshop: Mapping[str, Any],
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
        or environment["schema"] != _WORKSHOP_ENV_SCHEMA
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
            "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
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
        or environment["limitations"] != _LIMITATIONS
    ):
        raise AdmissionEvidenceError("workshop environment identity changed")

    isolation = environment["isolation"]
    if (
        canonical_digest(isolation)
        != "sha256:3ad1885c1c6e058b07e376a831a749b8f0a7d2b6b38fc2bc5d08ac0c3741cf36"
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
        or isolation["environment"]["OPENCLAW_NO_RESPAWN"] != "1"
        or isolation["environment"]["npm_config_offline"] != "true"
    ):
        raise AdmissionEvidenceError("workshop isolation changed")

    specs = [
        (
            "setup",
            "setup",
            "aragorn-openclaw-contained-workshop-setup-v1",
            "/probe/plug01-probe.mjs",
            False,
            10_765,
            _WORKSHOP_SETUP_DIGEST,
            "aragorn/openclaw-contained-plug01-setup-evidence/v1",
            workshop["consumed_setup"]["recorded_at"],
        ),
        (
            "evaluation",
            "run",
            "aragorn-openclaw-contained-workshop-evaluation-v1",
            "/probe/workshop-bypass-probe.mjs",
            True,
            42_678,
            _WORKSHOP_EVIDENCE_DIGEST,
            _WORKSHOP_SCHEMA,
            workshop["recorded_at"],
        ),
    ]
    containers = environment["containers"]
    if len(containers) != len(specs) or len(
        {container["id"] for container in containers}
    ) != len(specs):
        raise AdmissionEvidenceError("workshop container count changed")
    common_mounts = {
        "/probe": (
            "aragorn-openclaw-2026-7-1-contained-workshop-probe-v1",
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
            role,
            mode,
            name,
            probe_path,
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
            or container["profile"] != "workshop-bypass"
            or container["role"] != role
            or container["mode"] != mode
            or container["name"] != name
            or container["command"] != ["/usr/local/bin/node", probe_path, mode]
            or container["output"]
            != {
                "bytes": output_bytes,
                "digest": output_digest,
                "recorded_at": output_time,
                "schema": output_schema,
            }
        ):
            raise AdmissionEvidenceError("workshop container identity changed")
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
            raise AdmissionEvidenceError("workshop container state changed")
        mounts = {mount["destination"]: mount for mount in container["mounts"]}
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
                "source": "aragorn-openclaw-2026-7-1-contained-workshop-state-v1",
                "type": "volume",
            }
            or mounts["/profile/state/extensions"]
            != {
                "destination": "/profile/state/extensions",
                "read_only": extensions_read_only,
                "source": (
                    "aragorn-openclaw-2026-7-1-contained-workshop-extensions-v1"
                ),
                "type": "volume",
            }
        ):
            raise AdmissionEvidenceError("workshop mount isolation changed")

    if _time(containers[0]["state"]["finished_at"]) > _time(
        containers[1]["state"]["started_at"]
    ) or _time(environment["recorded_at"]) < max(
        _time(container["state"]["finished_at"]) for container in containers
    ):
        raise AdmissionEvidenceError("workshop container lineage is not causal")
    profile = {
        "image": environment["image"],
        "isolation": isolation,
        "mounts": [
            {"id": container["id"], "mounts": container["mounts"]}
            for container in containers
        ],
        "server": environment["docker"]["server"],
    }
    if environment["os_profile_digest"] != canonical_digest(profile):
        raise AdmissionEvidenceError("workshop environment binding changed")


def _verify_update_reload_coverage_v3(
    receipt: Mapping[str, Any],
    coverage: Mapping[str, Any],
    *,
    workshop: Mapping[str, Any],
    environment: Mapping[str, Any],
    prior_receipt: Mapping[str, Any],
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
        or coverage["schema"] != _COVERAGE_V3_SCHEMA
        or coverage["assurance"]
        != "SEMANTICALLY_VERIFIED_CUMULATIVE_ROUTE_FAILURE_NOT_INSTALLER_AUTHORITY"
        or coverage["decision"] != {"status": "FAIL", "installer_work_eligible": False}
        or coverage["recorded_at"] != receipt["recorded_at"]
        or coverage["route_inventory_canonical_digest"]
        != canonical_digest(route_inventory)
        or coverage["route_inventory_canonical_digest"]
        != _UPDATE_RELOAD_INVENTORY_DIGEST
        or coverage["source_evidence_digests"] != _WORKSHOP_SOURCES
        or coverage["source_receipt_digests"] != [_RECEIPT_V2_DIGEST]
    ):
        raise AdmissionEvidenceError("workshop coverage envelope changed")

    prior_coverage = _read_exact(
        evidence_cas,
        _COVERAGE_V2_DIGEST,
        _COVERAGE_V2_SCHEMA,
    )
    if coverage["partial_observations"] != prior_coverage[
        "partial_observations"
    ] or _time(coverage["recorded_at"]) < max(
        _time(prior_receipt["recorded_at"]),
        _time(workshop["recorded_at"]),
        _time(environment["recorded_at"]),
    ):
        raise AdmissionEvidenceError("workshop coverage provenance changed")

    expected_routes = []
    for prior in prior_coverage["routes"]:
        expected = dict(prior)
        if prior["id"] == _WORKSHOP_ROUTE:
            if (
                prior["status"] != "NOT_TESTED"
                or prior["source_evidence_digests"] != []
                or prior["source_receipt_digests"] != []
            ):
                raise AdmissionEvidenceError("workshop route was not additive")
            expected["source_evidence_digests"] = _WORKSHOP_SOURCES
            expected["status"] = "FAIL"
        expected_routes.append(expected)
    if coverage["routes"] != expected_routes:
        raise AdmissionEvidenceError("workshop coverage was not derived exactly")
    failures = [route["id"] for route in expected_routes if route["status"] == "FAIL"]
    passes = [route["id"] for route in expected_routes if route["status"] == "PASS"]
    if (
        failures != [_WORKSHOP_ROUTE]
        or sum("/update/" in route for route in passes) != 3
        or sum("/reload/" in route for route in passes) != 6
    ):
        raise AdmissionEvidenceError("workshop coverage boundary changed")

    implementation_digest = (
        "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    )
    configuration = {
        "failed_route_id": _WORKSHOP_ROUTE,
        "route_inventory_canonical_digest": _UPDATE_RELOAD_INVENTORY_DIGEST,
        "source_evidence_digests": _WORKSHOP_SOURCES,
        "source_receipt_digests": [_RECEIPT_V2_DIGEST],
    }
    expected_runtime = prior_receipt["bindings"]["runtime"]
    if expected_runtime != {
        "commit": environment["runtime"]["commit"],
        "name": environment["runtime"]["name"],
        "repository_url": "https://github.com/openclaw/openclaw",
        "source_tree_digest": environment["runtime"]["source_tree_digest"],
        "version": environment["runtime"]["version"],
    }:
        raise AdmissionEvidenceError("workshop source runtime binding changed")
    expected_bindings = {
        "runtime": expected_runtime,
        "adapter": {
            "name": "openclaw-update-reload-route-coverage-v3",
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
                    "failed_route_id": _WORKSHOP_ROUTE,
                    "source_evidence_digests": _WORKSHOP_SOURCES,
                    "source_receipt_digests": [_RECEIPT_V2_DIGEST],
                }
            ),
            "policy_digest": prior_receipt["bindings"]["aragorn"]["policy_digest"],
        },
    }
    if receipt["bindings"] != expected_bindings:
        raise AdmissionEvidenceError("workshop coverage bindings changed")
