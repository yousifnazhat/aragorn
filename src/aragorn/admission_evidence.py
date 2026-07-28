"""Semantic verification for retained partial OpenClaw admission claims."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .admission_conformance import (
    AdmissionConformanceError,
    validate_admission_conformance,
)
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest

_MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
_PROBE_SCHEMA = "aragorn/openclaw-contained-restart-probe-evidence/v1"
_ENV_SCHEMA = "aragorn/openclaw-contained-restart-environment-evidence/v1"
_PROBE_DIGEST = (
    "sha256:f9b08c63b414b0f91b5cc14deeb91a86a8a0b4aa3151e52702395004dde7dcb3"
)
_ENV_DIGEST = "sha256:e67b2522a705d9f9efbd447da68aae61af6964f51dd9275d2d956688389ebbfa"
_EVIDENCE_PAIR = sorted((_ENV_DIGEST, _PROBE_DIGEST))
_ADMITTED_DIGEST = (
    "sha256:5a951f65ad92bc209f9a00139fb88e38015fab9b5ac3035407a027a7d502853d"
)
_TEST_TOKEN = "aragorn-contained-restart-token-v1"
_INVALID_TEST_TOKEN = "aragorn-invalid-test-token-v1"
_ARAGORN_BINDING = {
    "implementation_digest": "sha256:979f1a06b87e26459faba52ce7bb94ceb89e3a39e212c7d2e4f6a418e41d9a71",
    "policy_digest": "sha256:f23061d06e0f2d28357f74989b9ea21f7270882d60963d60341a3494a98ec764",
}
_STATUSES = {
    "DET-01/identical-canonical-input-replay": "NOT_TESTED",
    "ADM-01/exact-admitted-bytes": "NOT_TESTED",
    "ADM-02/install": "PASS",
    "ADM-02/update": "NOT_TESTED",
    "ADM-02/direct-write": "PASS",
    "ADM-02/rename": "PASS",
    "ADM-02/symlink": "PASS",
    "ADM-02/auto-discovery": "PASS",
    "ADM-02/reload": "NOT_TESTED",
    "ADM-02/restart": "PASS",
    "ADM-03/policy-failure": "PASS",
    "ADM-03/policy-tampering": "PASS",
}
_REASONS = {
    "DET-01/identical-canonical-input-replay": ["IDENTICAL_REPLAY_NOT_TESTED"],
    "ADM-01/exact-admitted-bytes": ["EXACT_ACTIVATED_BYTES_NOT_TESTED"],
    "ADM-02/update": ["UPDATE_PATH_NOT_TESTED"],
    "ADM-02/reload": ["LIVE_RELOAD_NOT_TESTED"],
}
_UPDATE_PROBE_SCHEMA = "aragorn/openclaw-contained-update-probe-evidence/v1"
_UPDATE_ENV_SCHEMA = "aragorn/openclaw-contained-update-environment-evidence/v1"
_UPDATE_PROBE_DIGEST = (
    "sha256:2a6cbc2bbd6fa46b4addca029377d5d4265d698e2aa376858e32b80319310cdb"
)
_UPDATE_ENV_DIGEST = (
    "sha256:1c5fa32556e4d6d19b7bb54e92f1da5702c1700c0331b53fd380174e28e590aa"
)
_UPDATE_EVIDENCE_PAIR = sorted((_UPDATE_ENV_DIGEST, _UPDATE_PROBE_DIGEST))
_UPDATE_SCENARIO = "ADM-02/update"
_UPDATE_ROUTE = "ADM-02/update/archive-source-force-replacement"
_UPDATE_REASON = ["UPDATE_ROUTE_COVERAGE_INCOMPLETE"]
_OUTSIDE_UPDATE_REASON = ["SCENARIO_OUTSIDE_UPDATE_SLICE"]
_UPDATE_RECEIPT_REASONS = {
    "DET-01/identical-canonical-input-replay": ["IDENTICAL_REPLAY_NOT_TESTED"],
    "ADM-01/exact-admitted-bytes": ["EXACT_ACTIVATED_BYTES_NOT_TESTED"],
    "ADM-02/install": _OUTSIDE_UPDATE_REASON,
    _UPDATE_SCENARIO: _UPDATE_REASON,
    "ADM-02/direct-write": _OUTSIDE_UPDATE_REASON,
    "ADM-02/rename": _OUTSIDE_UPDATE_REASON,
    "ADM-02/symlink": _OUTSIDE_UPDATE_REASON,
    "ADM-02/auto-discovery": _OUTSIDE_UPDATE_REASON,
    "ADM-02/reload": _OUTSIDE_UPDATE_REASON,
    "ADM-02/restart": _OUTSIDE_UPDATE_REASON,
    "ADM-03/policy-failure": _OUTSIDE_UPDATE_REASON,
    "ADM-03/policy-tampering": _OUTSIDE_UPDATE_REASON,
}
_UPDATE_IMPLEMENTATION = {
    "contained_policy_probe_digest": (
        "sha256:da45089c199c5f749c94c88d19858fcb1b2c41236d965961782496b57fafe985"
    ),
    "route_inventory_digest": (
        "sha256:a5d2e53d14d0b56a2e4f335eeaf034f31f7c787bd8bfa09e4fe442d9f6363a6a"
    ),
    "update_probe_digest": (
        "sha256:12897fd5b4bea78161acf6f189ff71f768d5823c916b284c42bf7790c4528515"
    ),
}
_UPDATE_ADAPTER_IMPLEMENTATION_DIGEST = (
    "sha256:40c42f2908761ac5eda46d3d082546656926a8fe5cccfdc7ee92d62ce7b6267b"
)
_UPDATE_CONFIG_DIGEST = (
    "sha256:be5741ac8aa25f91c66d743ecee5c9722cb9934fdf8a3b2ba4a90120b239c79a"
)
_UPDATE_OS_PROFILE_DIGEST = (
    "sha256:53e934f187ae1da7bd8be41ba2e5d8d063e1e1e2784a234144cbedfe2213f256"
)
_LIVE_PROBE_SCHEMA = "aragorn/openclaw-contained-live-reload-probe-evidence/v1"
_LIVE_ENV_SCHEMA = (
    "aragorn/openclaw-contained-live-reload-environment-evidence/v1"
)
_LIVE_PROBE_DIGEST = (
    "sha256:b974afedbc3ecd12afa52dbc7aaf335c451cc7780ea77d1190c6e687e9d9e47f"
)
_LIVE_ENV_DIGEST = (
    "sha256:643e37646942279d46f1cee783baefe0eabcb3253fe9982ee695490af98b62ad"
)
_LIVE_EVIDENCE_PAIR = sorted((_LIVE_ENV_DIGEST, _LIVE_PROBE_DIGEST))
_OUTSIDE_LIVE_REASON = ["SCENARIO_OUTSIDE_LIVE_RELOAD_SLICE"]
_LIVE_RECEIPT_REASONS = {
    "DET-01/identical-canonical-input-replay": ["IDENTICAL_REPLAY_NOT_TESTED"],
    "ADM-01/exact-admitted-bytes": ["EXACT_ACTIVATED_BYTES_NOT_TESTED"],
    "ADM-02/install": _OUTSIDE_LIVE_REASON,
    "ADM-02/update": ["UPDATE_ROUTE_COVERAGE_INCOMPLETE"],
    "ADM-02/direct-write": _OUTSIDE_LIVE_REASON,
    "ADM-02/rename": _OUTSIDE_LIVE_REASON,
    "ADM-02/symlink": _OUTSIDE_LIVE_REASON,
    "ADM-02/auto-discovery": _OUTSIDE_LIVE_REASON,
    "ADM-02/reload": ["RELOAD_ROUTE_COVERAGE_INCOMPLETE"],
    "ADM-02/restart": _OUTSIDE_LIVE_REASON,
    "ADM-03/policy-failure": _OUTSIDE_LIVE_REASON,
    "ADM-03/policy-tampering": _OUTSIDE_LIVE_REASON,
}
_LIVE_IMPLEMENTATION_DIGEST = (
    "sha256:9dd8d69ad951d0bcac5abf8a21fd30f8c686f3cc41959fd2935f046d46af64b5"
)
_LIVE_CONFIG_DIGEST = (
    "sha256:091b92e553f39f00cdad9e767238a24433ed853403883d3bcbd9937933bbaaa3"
)
_LIVE_OS_PROFILE_DIGEST = (
    "sha256:b149a14989574cd8735d9a5033ab9da215a5f2e6ffd37c1e41d9f0f779ed6c60"
)
_CONFIG_PROBE_SCHEMA = "aragorn/openclaw-contained-config-activation-probe-evidence/v1"
_CONFIG_ENV_SCHEMA = (
    "aragorn/openclaw-contained-config-activation-environment-evidence/v1"
)
_CONFIG_PROBE_DIGEST = (
    "sha256:a02ccd57bf98dd3035405511610604a3796d3d1e038ffdad0ba6a64344cfd29c"
)
_CONFIG_ENV_DIGEST = (
    "sha256:92fe0300aee9d2d23b1ccb7ac4e585bbda5c98c5406bccb8e3e192091a88c357"
)
_CONFIG_PRIOR_ADMISSION_DIGEST = (
    "sha256:a81138e1bec12e0471068aafe4eee0b625635de5d39ba6bc3665d8251b76f6af"
)
_CONFIG_EVIDENCE_SET = sorted(
    (
        _CONFIG_ENV_DIGEST,
        _CONFIG_PRIOR_ADMISSION_DIGEST,
        _CONFIG_PROBE_DIGEST,
    )
)
_OUTSIDE_CONFIG_REASON = ["SCENARIO_OUTSIDE_CONFIG_ACTIVATION_SLICE"]
_CONFIG_RECEIPT_REASONS = {
    "DET-01/identical-canonical-input-replay": ["IDENTICAL_REPLAY_NOT_TESTED"],
    "ADM-01/exact-admitted-bytes": ["EXACT_ACTIVATED_BYTES_NOT_TESTED"],
    "ADM-02/install": _OUTSIDE_CONFIG_REASON,
    "ADM-02/update": ["UPDATE_ROUTE_COVERAGE_INCOMPLETE"],
    "ADM-02/direct-write": _OUTSIDE_CONFIG_REASON,
    "ADM-02/rename": _OUTSIDE_CONFIG_REASON,
    "ADM-02/symlink": _OUTSIDE_CONFIG_REASON,
    "ADM-02/auto-discovery": _OUTSIDE_CONFIG_REASON,
    "ADM-02/reload": ["RELOAD_ROUTE_COVERAGE_INCOMPLETE"],
    "ADM-02/restart": _OUTSIDE_CONFIG_REASON,
    "ADM-03/policy-failure": _OUTSIDE_CONFIG_REASON,
    "ADM-03/policy-tampering": _OUTSIDE_CONFIG_REASON,
}
_CONFIG_IMPLEMENTATION_DIGEST = (
    "sha256:9690cda8f542fa5652e1d45b8bc7bc0e0248d2485a60b4918d27ab9265f635a1"
)
_CONFIG_OS_PROFILE_DIGEST = (
    "sha256:f896b6f732dd4c4bc479821e6fca0d728135e9ae8c483fbcc4f6c600f248cfca"
)
_OPENCLAW_COMMIT = "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4"
_OPENCLAW_RUNTIME_TREE = (
    "sha256:475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c"
)
_OPENCLAW_PLATFORM_MANIFEST = (
    "sha256:1df790a7d590f617d0d3c2cd84cbe18b5400ff972dd9701670f7e5a4f1634e52"
)
_RFC3339_EXTRA_PRECISION = re.compile(
    r"(\.[0-9]{6})[0-9]+(?=Z$|[+-][0-9]{2}:[0-9]{2}$)"
)


class AdmissionEvidenceError(AdmissionConformanceError):
    """Retained partial OpenClaw admission evidence is invalid."""


def verify_openclaw_restart_evidence(
    document: Mapping[str, Any], *, evidence_cas: CAS
) -> None:
    """Verify only ADM-02/restart; carried claims and installer authority stay out of scope."""
    try:
        status = validate_admission_conformance(document)
        if status != "NOT_TESTED" or document["decision"] != {
            "status": "NOT_TESTED",
            "installer_work_eligible": False,
        }:
            raise AdmissionEvidenceError(
                "partial semantic closure cannot grant installer authority"
            )
        formal = {
            f"{item['id']}/{scenario['id']}": scenario
            for item in document["properties"]
            for scenario in item["scenarios"]
        }
        if {key: value["status"] for key, value in formal.items()} != _STATUSES:
            raise AdmissionEvidenceError("partial profile claim set changed")
        reasons = {
            key: value["reason_codes"]
            for key, value in formal.items()
            if value["status"] == "NOT_TESTED"
        }
        if reasons != _REASONS:
            raise AdmissionEvidenceError("partial profile reason set changed")
        for key, scenario in formal.items():
            expected = _EVIDENCE_PAIR if _STATUSES[key] == "PASS" else []
            if scenario["evidence_digests"] != expected:
                raise AdmissionEvidenceError(
                    f"{key} does not bind the exact retained proof pair"
                )
        probe = _read_exact(evidence_cas, _PROBE_DIGEST, _PROBE_SCHEMA)
        environment = _read_exact(evidence_cas, _ENV_DIGEST, _ENV_SCHEMA)
        _verify_bindings(document, probe, environment)
        _verify_carried_context(probe)
        _verify_restart(probe)
        _verify_environment(probe, environment)
    except AdmissionEvidenceError:
        raise
    except (
        AdmissionConformanceError,
        CASError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid partial admission semantic closure: {exc}"
        ) from exc


def verify_openclaw_update_slice_evidence(
    document: Mapping[str, Any], *, evidence_cas: CAS
) -> None:
    """Verify one denied update route without promoting formal ADM-02/update."""

    try:
        if (
            validate_admission_conformance(document) != "NOT_TESTED"
            or document["decision"]
            != {"status": "NOT_TESTED", "installer_work_eligible": False}
        ):
            raise AdmissionEvidenceError(
                "update slice cannot grant installer authority"
            )
        formal = {
            f"{item['id']}/{scenario['id']}": scenario
            for item in document["properties"]
            for scenario in item["scenarios"]
        }
        if (
            set(formal) != set(_UPDATE_RECEIPT_REASONS)
            or any(item["status"] != "NOT_TESTED" for item in formal.values())
            or {
                key: item["reason_codes"] for key, item in formal.items()
            }
            != _UPDATE_RECEIPT_REASONS
        ):
            raise AdmissionEvidenceError("update-slice formal claim set changed")
        for key, scenario in formal.items():
            expected = _UPDATE_EVIDENCE_PAIR if key == _UPDATE_SCENARIO else []
            if scenario["evidence_digests"] != expected:
                raise AdmissionEvidenceError(
                    f"{key} does not bind the exact update-slice evidence"
                )
        probe = _read_exact(
            evidence_cas,
            _UPDATE_PROBE_DIGEST,
            _UPDATE_PROBE_SCHEMA,
        )
        environment = _read_exact(
            evidence_cas,
            _UPDATE_ENV_DIGEST,
            _UPDATE_ENV_SCHEMA,
        )
        _verify_update_bindings(document, probe, environment)
        _verify_update_probe(probe)
        _verify_update_environment(probe, environment)
    except AdmissionEvidenceError:
        raise
    except (
        AdmissionConformanceError,
        CASError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid retained update-slice evidence: {exc}"
        ) from exc


def verify_openclaw_live_reload_slice_evidence(
    document: Mapping[str, Any], *, evidence_cas: CAS
) -> None:
    """Verify one admitted update and two live-reload routes."""

    try:
        if (
            validate_admission_conformance(document) != "NOT_TESTED"
            or document["decision"]
            != {"status": "NOT_TESTED", "installer_work_eligible": False}
        ):
            raise AdmissionEvidenceError(
                "live-reload slice cannot grant installer authority"
            )
        formal = {
            f"{item['id']}/{scenario['id']}": scenario
            for item in document["properties"]
            for scenario in item["scenarios"]
        }
        if (
            set(formal) != set(_LIVE_RECEIPT_REASONS)
            or any(item["status"] != "NOT_TESTED" for item in formal.values())
            or {
                key: item["reason_codes"] for key, item in formal.items()
            }
            != _LIVE_RECEIPT_REASONS
        ):
            raise AdmissionEvidenceError("live-reload formal claim set changed")
        targeted = {"ADM-02/update", "ADM-02/reload"}
        for key, scenario in formal.items():
            expected = _LIVE_EVIDENCE_PAIR if key in targeted else []
            if scenario["evidence_digests"] != expected:
                raise AdmissionEvidenceError(
                    f"{key} does not bind the exact live-reload evidence"
                )
        probe = _read_exact(
            evidence_cas,
            _LIVE_PROBE_DIGEST,
            _LIVE_PROBE_SCHEMA,
        )
        environment = _read_exact(
            evidence_cas,
            _LIVE_ENV_DIGEST,
            _LIVE_ENV_SCHEMA,
        )
        _verify_live_reload_bindings(document, probe, environment)
        _verify_live_reload_probe(probe)
        _verify_live_reload_environment(probe, environment)
    except AdmissionEvidenceError:
        raise
    except (
        AdmissionConformanceError,
        CASError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid retained live-reload evidence: {exc}"
        ) from exc


def verify_openclaw_config_activation_slice_evidence(
    document: Mapping[str, Any], *, evidence_cas: CAS
) -> None:
    """Verify one config activation and its same-session invalidation."""

    try:
        if validate_admission_conformance(document) != "NOT_TESTED" or document[
            "decision"
        ] != {"status": "NOT_TESTED", "installer_work_eligible": False}:
            raise AdmissionEvidenceError(
                "config-activation slice cannot grant installer authority"
            )
        formal = {
            f"{item['id']}/{scenario['id']}": scenario
            for item in document["properties"]
            for scenario in item["scenarios"]
        }
        if (
            set(formal) != set(_CONFIG_RECEIPT_REASONS)
            or any(item["status"] != "NOT_TESTED" for item in formal.values())
            or {key: item["reason_codes"] for key, item in formal.items()}
            != _CONFIG_RECEIPT_REASONS
        ):
            raise AdmissionEvidenceError("config-activation formal claim set changed")
        targeted = {"ADM-02/update", "ADM-02/reload"}
        for key, scenario in formal.items():
            expected = _CONFIG_EVIDENCE_SET if key in targeted else []
            if scenario["evidence_digests"] != expected:
                raise AdmissionEvidenceError(
                    f"{key} does not bind the exact config-activation evidence"
                )
        probe = _read_exact(
            evidence_cas,
            _CONFIG_PROBE_DIGEST,
            _CONFIG_PROBE_SCHEMA,
        )
        environment = _read_exact(
            evidence_cas,
            _CONFIG_ENV_DIGEST,
            _CONFIG_ENV_SCHEMA,
        )
        prior = _read_exact(
            evidence_cas,
            _CONFIG_PRIOR_ADMISSION_DIGEST,
            "aragorn/openclaw-contained-profile-probe-evidence/v1",
        )
        _verify_config_activation_bindings(document, probe, environment, prior)
        _verify_config_activation_probe(probe)
        _verify_config_activation_environment(probe, environment)
    except AdmissionEvidenceError:
        raise
    except (
        AdmissionConformanceError,
        CASError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid retained config-activation evidence: {exc}"
        ) from exc


def _read_exact(cas: CAS, digest: str, schema: str) -> dict[str, Any]:
    raw = cas.read(digest, max_bytes=_MAX_EVIDENCE_BYTES)
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(f"evidence is invalid JSON: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema") != schema:
        raise AdmissionEvidenceError("evidence schema pair is unsupported")
    if _canonical_bytes(document) + b"\n" != raw:
        raise AdmissionEvidenceError("evidence is not canonical JSON plus LF")
    return document


def _verify_bindings(
    receipt: Mapping[str, Any], probe: Mapping[str, Any], environment: Mapping[str, Any]
) -> None:
    if receipt["recorded_at"] != probe["recorded_at"]:
        raise AdmissionEvidenceError("receipt and probe timestamps differ")
    runtime = probe["runtime"]
    expected_runtime = {
        "name": "openclaw-contained",
        "version": "2026.7.1",
        "repository_url": "https://github.com/openclaw/openclaw",
        "commit": runtime["commit"],
        "source_tree_digest": runtime["runtime_tree"]["tree_digest"],
    }
    if receipt["bindings"]["runtime"] != expected_runtime:
        raise AdmissionEvidenceError("runtime binding changed")
    adapter = probe["adapter"]
    if (
        adapter["configuration_digest"] != canonical_digest(adapter["configuration"])
        or adapter["implementation_digest"]
        != canonical_digest(adapter["implementation"])
        or receipt["bindings"]["adapter"]
        != {
            "name": "openclaw-contained-profile-restart",
            "implementation_digest": adapter["implementation_digest"],
            "configuration_digest": adapter["configuration_digest"],
        }
    ):
        raise AdmissionEvidenceError("adapter binding changed")
    image_digest = environment["container"]["image"]["platform_manifest_digest"]
    if (
        environment["os_profile_digest"] != canonical_digest(environment["isolation"])
        or receipt["bindings"]["environment"]
        != {
            "worker_digest": image_digest,
            "os_profile_digest": environment["os_profile_digest"],
        }
        or receipt["bindings"]["aragorn"] != _ARAGORN_BINDING
    ):
        raise AdmissionEvidenceError("environment or Aragorn binding changed")


def _verify_carried_context(probe: Mapping[str, Any]) -> None:
    adm03_profile = probe["adm03_profile"]
    adm03 = adm03_profile["evidence"]
    if (
        adm03_profile["digest"] != _line_digest(adm03)
        or adm03["schema"] != "aragorn/openclaw-contained-adm03-probe-evidence/v1"
        or adm03["runtime"] != probe["runtime"]
        or adm03["adapter"]["configuration"] != probe["adapter"]["configuration"]
    ):
        raise AdmissionEvidenceError("carried ADM-03 context binding changed")
    if [(item["id"], item["status"]) for item in adm03["scenarios"]] != [
        ("ADM-03/policy-failure", "PASS"),
        ("ADM-03/policy-tampering", "PASS"),
    ]:
        raise AdmissionEvidenceError("carried ADM-03 context changed")
    contained_profile = adm03["contained_profile"]
    contained = contained_profile["evidence"]
    if (
        contained_profile["digest"] != _line_digest(contained)
        or contained["schema"] != "aragorn/openclaw-contained-profile-probe-evidence/v1"
        or contained["runtime"] != probe["runtime"]
        or contained["adapter"]["configuration"] != probe["adapter"]["configuration"]
    ):
        raise AdmissionEvidenceError("carried contained context binding changed")
    if [(item["id"], item["status"]) for item in contained["scenarios"]] != [
        ("ADM-01/exact-admitted-bytes", "PASS"),
        ("ADM-02/install", "PASS"),
        ("ADM-02/direct-write", "PASS"),
        ("ADM-02/rename", "PASS"),
        ("ADM-02/symlink", "PASS"),
        ("ADM-02/auto-discovery", "PASS"),
        ("ADM-02/restart", "PASS"),
    ]:
        raise AdmissionEvidenceError("carried contained context changed")


def _verify_restart(probe: Mapping[str, Any]) -> None:
    if [(item["id"], item["status"]) for item in probe["scenarios"]] != [
        ("ADM-02/restart", "PASS")
    ]:
        raise AdmissionEvidenceError("outer restart claim changed")
    scenario = probe["scenarios"][0]
    commands, evidence = scenario["commands"], scenario["evidence"]
    response = evidence["restart_response"]
    restart_command = commands["restart"]
    if (
        restart_command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "restart",
            "--safe",
            "--json",
        ]
        or restart_command["exit_code"] != 0
        or restart_command["stdout_bytes"] != 0
        or json.loads(restart_command["stderr"]) != response
        or response["ok"] is not True
        or response["result"] != "scheduled"
        or response["preflight"]
        != {
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
        }
        or {
            key: response["restart"][key]
            for key in ("coalesced", "mode", "ok", "pid", "reason", "signal")
        }
        != {
            "coalesced": False,
            "mode": "emit",
            "ok": True,
            "pid": 1,
            "reason": "gateway.restart.safe",
            "signal": "SIGUSR1",
        }
    ):
        raise AdmissionEvidenceError("safe restart was not proven")
    expected_auth_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "system.info",
        "--token",
        _INVALID_TEST_TOKEN,
        "--json",
        "--timeout",
        "5000",
    ]
    for key in ("authentication_before", "authentication_after"):
        auth = commands[key]
        if (
            auth["status"] != "PASS"
            or auth["command"]["argv"] != expected_auth_argv
            or auth["command"]["exit_code"] != 1
            or "unauthorized" not in auth["command"]["stderr"]
            or auth["response"]["ok"] is not False
            or auth["response"]["error"]["code"] != 1008
        ):
            raise AdmissionEvidenceError("authentication denial changed")
    lifecycle = evidence["lifecycle"]
    order = (
        "first_ready",
        "signal",
        "restarting",
        "shutdown",
        "restart_mode",
        "second_ready",
    )
    offsets = [lifecycle[key]["offset"] for key in order]
    if offsets != sorted(set(offsets)):
        raise AdmissionEvidenceError("restart lifecycle is not strictly ordered")
    times = [_time(lifecycle[key]["time"]) for key in order]
    restart_started = _time(commands["restart"]["started_at"])
    restart_completed = _time(commands["restart"]["completed_at"])
    if (
        times != sorted(times)
        or restart_started > times[1]
        or times[2] > restart_completed
        or restart_completed > times[3]
    ):
        raise AdmissionEvidenceError("restart lifecycle timing is not causal")
    messages = [lifecycle[key]["message"] for key in order]
    if (
        messages[:3]
        != [
            "gateway ready",
            "signal SIGUSR1 received",
            "received SIGUSR1; restarting",
        ]
        or not messages[3].startswith("shutdown completed cleanly ")
        or not messages[4].startswith("restart mode: in-process restart ")
        or messages[5] != "gateway ready"
    ):
        raise AdmissionEvidenceError("restart lifecycle markers changed")
    if (
        lifecycle["process_before"] != lifecycle["process_after"]
        or lifecycle["process_before"]
        != {
            "cmdline": ["openclaw-gateway"],
            "pid": 1,
            "start_time_ticks": lifecycle["process_before"]["start_time_ticks"],
        }
        or evidence["protected_state_before"] != evidence["protected_state_after"]
        or evidence["skills"]["raw_bytes_equal"] is not True
        or evidence["skills"]["projection_before"]
        != evidence["skills"]["projection_after"]
    ):
        raise AdmissionEvidenceError("post-restart protected state changed")
    clients = evidence["rpc_clients"]
    skills_before = commands["skills_before"]
    skills_after = commands["skills_after"]
    expected_skills_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "skills.status",
        "--json",
        "--timeout",
        "5000",
        "--params",
        '{"agentId":"main"}',
    ]
    for key in ("skills_before", "skills_after"):
        if clients[key] != {
            field: commands[key][field]
            for field in ("completed_at", "pid", "started_at")
        }:
            raise AdmissionEvidenceError("RPC client binding changed")
    if (
        clients["skills_before"]["pid"] <= 1
        or clients["skills_after"]["pid"] <= 1
        or clients["skills_before"]["pid"] == clients["skills_after"]["pid"]
        or _time(clients["skills_before"]["completed_at"])
        > _time(commands["restart"]["started_at"])
        or _time(clients["skills_after"]["started_at"])
        < _time(lifecycle["second_ready"]["time"])
        or skills_before["argv"] != expected_skills_argv
        or skills_after["argv"] != expected_skills_argv
        or skills_before["exit_code"] != 0
        or skills_after["exit_code"] != 0
        or skills_before["stdout_bytes"] <= 0
        or skills_before["stdout_bytes"] != skills_after["stdout_bytes"]
        or skills_before["stdout_digest"] != skills_after["stdout_digest"]
    ):
        raise AdmissionEvidenceError("fresh post-restart RPC was not proven")
    system_info = evidence["system_info"]
    expected_system_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "system.info",
        "--json",
        "--timeout",
        "5000",
    ]
    if any(
        commands[key]["argv"] != expected_system_argv
        or commands[key]["exit_code"] != 0
        or commands[key]["stdout_bytes"] <= 0
        for key in ("system_before", "system_after")
    ):
        raise AdmissionEvidenceError("system identity RPC changed")
    if set(system_info) != {"before", "after"} or any(
        item["pid"] != 1
        or item["port"] != 18789
        or item["platform"] != "linux"
        or item["nodeVersion"] != "v24.16.0"
        for item in system_info.values()
    ):
        raise AdmissionEvidenceError("gateway system identity changed")
    _verify_skill_projection(evidence["skills"]["projection_after"])
    protected = evidence["protected_state_before"]
    if (
        protected["admitted_digest"] != _ADMITTED_DIGEST
        or protected["implementation"] != probe["adapter"]["implementation"]
        or protected["policy_digest"]
        != probe["adapter"]["implementation"]["contained_probe_digest"]
    ):
        raise AdmissionEvidenceError("protected restart identity changed")
    _verify_gateway_log(evidence["gateway_log"], lifecycle, order)


def _verify_skill_projection(projection: Mapping[str, Any]) -> None:
    if (
        projection["agent_id"] != "main"
        or projection["agent_skill_filter"] != ["aragorn-admitted"]
        or projection["managed_skills_dir"] != "/profile/state/skills"
        or projection["workspace_dir"] != "/profile/workspace"
    ):
        raise AdmissionEvidenceError("skill projection context changed")
    admitted_entries = [
        item for item in projection["skills"] if item["name"] == "aragorn-admitted"
    ]
    expected_admitted = {
        "base_dir": "/profile/state/skills/aragorn-admitted",
        "blocked_by_agent_filter": False,
        "blocked_by_allowlist": False,
        "command_visible": True,
        "disabled": False,
        "eligible": True,
        "file_path": "/profile/state/skills/aragorn-admitted/SKILL.md",
        "model_visible": True,
        "name": "aragorn-admitted",
        "source": "openclaw-managed",
        "user_invocable": True,
    }
    if admitted_entries != [expected_admitted]:
        raise AdmissionEvidenceError("admitted skill projection changed")
    effective = [
        item
        for item in projection["skills"]
        if not item["disabled"]
        and not item["blocked_by_allowlist"]
        and not item["blocked_by_agent_filter"]
        and (item["eligible"] or item["model_visible"] or item["command_visible"])
    ]
    if effective != [expected_admitted]:
        raise AdmissionEvidenceError("effective admitted skill changed")
    if any(
        not item["blocked_by_agent_filter"]
        or item["model_visible"]
        or item["command_visible"]
        for item in projection["skills"]
        if item["name"] != "aragorn-admitted"
    ):
        raise AdmissionEvidenceError("unadmitted skill became visible")


def _verify_gateway_log(
    log: Mapping[str, Any],
    lifecycle: Mapping[str, Any],
    order: tuple[str, ...],
) -> None:
    raw = ("\n".join(log["lines"]) + "\n").encode("utf-8")
    if (
        len(raw) != log["bytes"]
        or "sha256:" + hashlib.sha256(raw).hexdigest() != log["digest"]
        or _TEST_TOKEN.encode() in raw
        or _INVALID_TEST_TOKEN.encode() in raw
    ):
        raise AdmissionEvidenceError("gateway log closure changed")
    records = {}
    offset = 0
    for line in log["lines"]:
        records[offset] = json.loads(line, object_pairs_hook=_reject_duplicates)
        offset += len(line.encode("utf-8")) + 1
    if offset != log["bytes"] or any(
        records[lifecycle[key]["offset"]].get("message") != lifecycle[key]["message"]
        or records[lifecycle[key]["offset"]].get("time") != lifecycle[key]["time"]
        or records[lifecycle[key]["offset"]].get("traceId")
        != lifecycle[key]["trace_id"]
        or lifecycle[key]["connection_id"] is not None
        or lifecycle[key]["request_id"] is not None
        for key in order
    ):
        raise AdmissionEvidenceError("lifecycle markers are not bound to the log")


def _verify_environment(
    probe: Mapping[str, Any], environment: Mapping[str, Any]
) -> None:
    container = environment["container"]
    execution = environment["container"]["probe_exec"]
    isolation = environment["isolation"]
    state = container["state"]
    expected_command = [
        "/bin/sh",
        "-c",
        "/usr/local/bin/node /probe/contained-probe.mjs > "
        "/tmp/contained-profile.json && /usr/local/bin/node "
        "/probe/adm03-probe.mjs > /tmp/contained-adm03.json && exec "
        "/usr/local/bin/node /runtime/lib/node_modules/openclaw/openclaw.mjs "
        "gateway run --allow-unconfigured --auth token --bind loopback "
        "--port 18789 --tailscale off --ws-log full",
    ]
    if (
        execution["command"] != ["/usr/local/bin/node", "/probe/restart-probe.mjs"]
        or execution["exit_code"] != 0
        or execution["recorded_at"] != probe["recorded_at"]
        or execution["stdout"] != {"bytes": 125_866, "digest": _PROBE_DIGEST}
        or execution["user"] != "1000:1000"
        or container["command"] != expected_command
        or container["working_dir"] != "/profile/workspace"
        or (state["status"], state["exit_code"], state["oom_killed"])
        != ("exited", 0, False)
    ):
        raise AdmissionEvidenceError("probe execution environment changed")
    controls = {
        "cap_drop": ["ALL"],
        "cgroupns_mode": "private",
        "devices": [],
        "ipc_mode": "private",
        "memory_bytes": 1_073_741_824,
        "memory_swap_bytes": 1_073_741_824,
        "nano_cpus": 1_000_000_000,
        "network_mode": "none",
        "no_new_privileges": True,
        "pids_limit": 128,
        "privileged": False,
        "read_only_rootfs": True,
        "runtime": "runc",
        "user": "1000:1000",
    }
    expected_environment = {
        "HOME": "/profile/home",
        "NODE_VERSION": "24.16.0",
        "OPENCLAW_CONFIG_PATH": "/profile/config/openclaw.json",
        "OPENCLAW_GATEWAY_TOKEN": _TEST_TOKEN,
        "OPENCLAW_STATE_DIR": "/profile/state",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "YARN_VERSION": "1.22.22",
    }
    expected_tmpfs = {
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
    }
    expected_mounts = {
        "/acquisition": "aragorn-openclaw-2026-7-1-acquisition",
        "/probe": "aragorn-openclaw-2026-7-1-contained-probe-v7",
        "/profile/config": "aragorn-openclaw-2026-7-1-contained-profile-config-v1",
        "/profile/home/.agents": "aragorn-openclaw-2026-7-1-contained-guard-v1",
        "/profile/state/plugin-skills": (
            "aragorn-openclaw-2026-7-1-contained-guard-v1"
        ),
        "/profile/state/skills": "aragorn-openclaw-2026-7-1-contained-admitted-v1",
        "/profile/workspace/.agents": ("aragorn-openclaw-2026-7-1-contained-guard-v1"),
        "/profile/workspace/skills": ("aragorn-openclaw-2026-7-1-contained-guard-v1"),
        "/runtime": "aragorn-openclaw-2026-7-1-runtime",
    }
    mounts = {
        item["destination"]: {
            "read_only": item["read_only"],
            "source": item["source"],
            "type": item["type"],
        }
        for item in isolation["mounts"]
    }
    if (
        any(isolation[key] != value for key, value in controls.items())
        or isolation["environment"] != expected_environment
        or isolation["tmpfs"] != expected_tmpfs
        or isolation["ulimits"] != [{"hard": 256, "name": "nofile", "soft": 256}]
        or len(isolation["mounts"]) != 9
        or len(mounts) != 9
        or mounts
        != {
            destination: {
                "read_only": True,
                "source": source,
                "type": "volume",
            }
            for destination, source in expected_mounts.items()
        }
        or container["image"]
        != {
            "index_digest": (
                "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
            ),
            "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
            "platform_manifest_digest": (
                "sha256:1df790a7d590f617d0d3c2cd84cbe18b5400ff972dd9701670f7e5a4f1634e52"
            ),
            "reference": (
                "node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
            ),
        }
        or environment["docker"]["platform_manifest_resolution"]["digest"]
        != container["image"]["platform_manifest_digest"]
        or environment["docker"]["assurance"]
        != "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"
    ):
        raise AdmissionEvidenceError("contained isolation proof changed")


def _verify_update_bindings(
    receipt: Mapping[str, Any],
    probe: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> None:
    if (
        receipt["recorded_at"] != probe["recorded_at"]
        or environment["recorded_at"] != probe["recorded_at"]
    ):
        raise AdmissionEvidenceError("update evidence timestamps differ")
    if receipt["bindings"] != {
        "runtime": {
            "name": "openclaw-contained",
            "version": "2026.7.1",
            "repository_url": "https://github.com/openclaw/openclaw",
            "commit": _OPENCLAW_COMMIT,
            "source_tree_digest": _OPENCLAW_RUNTIME_TREE,
        },
        "adapter": {
            "name": "openclaw-contained-update-slice",
            "implementation_digest": _UPDATE_ADAPTER_IMPLEMENTATION_DIGEST,
            "configuration_digest": _UPDATE_CONFIG_DIGEST,
        },
        "environment": {
            "worker_digest": _OPENCLAW_PLATFORM_MANIFEST,
            "os_profile_digest": _UPDATE_OS_PROFILE_DIGEST,
        },
        "aragorn": _ARAGORN_BINDING,
    }:
        raise AdmissionEvidenceError("update receipt bindings changed")
    adapter = probe["adapter"]
    if (
        adapter["configuration_digest"]
        != canonical_digest(adapter["configuration"])
        or adapter["configuration_digest"] != _UPDATE_CONFIG_DIGEST
        or adapter["implementation"] != _UPDATE_IMPLEMENTATION
        or adapter["implementation_digest"]
        != canonical_digest(adapter["implementation"])
        or adapter["implementation_digest"]
        != _UPDATE_ADAPTER_IMPLEMENTATION_DIGEST
    ):
        raise AdmissionEvidenceError("update adapter binding changed")


def _expected_update_policy_request() -> dict[str, Any]:
    source = "/profile/workspace/update-source"
    return {
        "openclawVersion": "2026.7.1",
        "origin": {"spec": source, "type": "path"},
        "protocolVersion": 1,
        "request": {
            "kind": "skill-install",
            "mode": "update",
            "requestedSpecifier": source,
        },
        "skill": {"installId": "path"},
        "source": {
            "authority": "user",
            "kind": "local-path",
            "mutable": True,
            "network": False,
        },
        "sourcePath": source,
        "sourcePathKind": "directory",
        "targetName": "aragorn-admitted",
        "targetType": "skill",
    }


def _verify_update_probe(probe: Mapping[str, Any]) -> None:
    if (
        probe["decision"]
        != {"installer_work_eligible": False, "status": "NOT_TESTED"}
        or probe["limitations"]
        != [
            "ONLY_LOCAL_DIRECTORY_GLOBAL_FORCE_REPLACEMENT_EXECUTED",
            "OTHER_UPDATE_PATHS_AND_LIVE_RELOAD_REMAIN_NOT_TESTED",
            "CONTAINED_DOCKER_ENVIRONMENT_NOT_INDEPENDENTLY_ATTESTED",
        ]
    ):
        raise AdmissionEvidenceError("update claim boundary changed")
    runtime = probe["runtime"]
    if (
        runtime["commit"] != _OPENCLAW_COMMIT
        or runtime["name"] != "openclaw-contained"
        or runtime["version"] != "2026.7.1"
        or runtime["runtime_tree"]
        != {
            "algorithm": "aragorn/runtime-tree/v1",
            "entry_count": 45856,
            "file_count": 45837,
            "symlink_count": 19,
            "total_bytes": 369317461,
            "tree_digest": _OPENCLAW_RUNTIME_TREE,
        }
        or runtime["source_tree"]
        != {
            "file_count": 8550,
            "total_bytes": 87679175,
            "tree_digest": (
                "sha256:"
                "f70f3b603e6ddb616e2d986a73d658b7b8b01795fa98db89355d06ba6776cea3"
            ),
        }
    ):
        raise AdmissionEvidenceError("update runtime binding changed")
    version = runtime["version_command"]
    if (
        version["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ]
        or version["exit_code"] != 0
        or version["signal"] is not None
        or version["error"] is not None
        or version["stderr"] != ""
        or version["stdout"] != "OpenClaw 2026.7.1 (2d2ddc4)\n"
        or not isinstance(version["pid"], int)
        or version["pid"] <= 1
    ):
        raise AdmissionEvidenceError("update runtime execution changed")

    scenario = probe["scenario"]
    command = scenario["command"]
    expected_request = _expected_update_policy_request()
    expected_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "skills",
        "install",
        "/profile/workspace/update-source",
        "--as",
        "aragorn-admitted",
        "--force",
        "--global",
    ]
    if (
        scenario["id"] != _UPDATE_ROUTE
        or scenario["status"] != "PASS"
        or command["argv"] != expected_argv
        or command["exit_code"] != 1
        or command["signal"] is not None
        or command["error"] is not None
        or command["stdout"]
        != (
            "Install policy target=skill:aragorn-admitted "
            "request=skill-install/update origin=path pathKind=directory "
            "source=local-path/user: blocked by install policy: "
            "Aragorn contained profile block\n"
        )
        or command["stderr"]
        != "blocked by install policy: Aragorn contained profile block\n"
        or not isinstance(command["pid"], int)
        or command["pid"] <= 1
        or command["pid"] == version["pid"]
    ):
        raise AdmissionEvidenceError("forced update denial changed")
    evidence = scenario["evidence"]
    managed = [
        {
            "gid": 1000,
            "mode": "700",
            "nlink": 3,
            "path": ".",
            "size": 60,
            "type": "directory",
            "uid": 1000,
        },
        {
            "gid": 1000,
            "mode": "700",
            "nlink": 2,
            "path": "aragorn-admitted",
            "size": 60,
            "type": "directory",
            "uid": 1000,
        },
        {
            "digest": (
                "sha256:"
                "5a951f65ad92bc209f9a00139fb88e38015fab9b5ac3035407a027a7d502853d"
            ),
            "gid": 1000,
            "mode": "600",
            "nlink": 1,
            "path": "aragorn-admitted/SKILL.md",
            "size": 104,
            "type": "file",
            "uid": 1000,
        },
    ]
    source = [
        {
            "gid": 1000,
            "mode": "700",
            "nlink": 2,
            "path": ".",
            "size": 60,
            "type": "directory",
            "uid": 1000,
        },
        {
            "digest": (
                "sha256:"
                "352a0bc83299c00b4729de03c3dd6fc8a15d70096fe72a40184ce5352c55fba7"
            ),
            "gid": 1000,
            "mode": "600",
            "nlink": 1,
            "path": "SKILL.md",
            "size": 128,
            "type": "file",
            "uid": 1000,
        },
    ]
    if (
        evidence["expected_policy_request"] != expected_request
        or evidence["policy_request"] != expected_request
        or evidence["managed_before"] != managed
        or evidence["managed_after"] != managed
        or evidence["source_before"] != source
        or evidence["source_after"] != source
        or evidence["write_preflight"]
        != {
            "digest": (
                "sha256:"
                "e9edf18672cae394a185c2bdf7ea294f89eec18ede9b36e1a71bbd13336a22dc"
            ),
            "path": "/profile/state/skills/aragorn-admitted/.write-proof",
            "removed": True,
        }
    ):
        raise AdmissionEvidenceError(
            "update request or writable managed-root identity changed"
        )
    if not (
        _time(version["started_at"])
        <= _time(version["completed_at"])
        <= _time(command["started_at"])
        <= _time(command["completed_at"])
        <= _time(probe["recorded_at"])
    ):
        raise AdmissionEvidenceError("update execution timing is not causal")


def _verify_update_environment(
    probe: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> None:
    container = environment["container"]
    execution = container["probe_exec"]
    state = container["state"]
    image = container["image"]
    if (
        environment["recorded_at"] != probe["recorded_at"]
        or execution
        != {
            "command": ["/usr/local/bin/node", "/probe/update-probe.mjs"],
            "exit_code": 0,
            "mode": "container-command",
            "recorded_at": probe["recorded_at"],
            "stdout": {
                "bytes": 5433,
                "digest": _UPDATE_PROBE_DIGEST,
            },
            "user": "1000:1000",
        }
        or container["command"] != execution["command"]
        or container["name"] != "aragorn-openclaw-contained-update-v1"
        or container["working_dir"] != "/profile/workspace"
        or state["status"] != "exited"
        or state["exit_code"] != 0
        or state["running"]
        or state["paused"]
        or state["restarting"]
        or state["oom_killed"]
        or state["dead"]
        or state["error"] != ""
    ):
        raise AdmissionEvidenceError("update probe execution environment changed")
    expected_image = {
        "id": (
            "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
        ),
        "index_digest": (
            "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
        ),
        "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
        "platform_manifest_digest": _OPENCLAW_PLATFORM_MANIFEST,
        "reference": (
            "node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
        ),
    }
    if image != expected_image:
        raise AdmissionEvidenceError("update container image changed")
    isolation = environment["isolation"]
    expected_mounts = [
        {
            "destination": "/probe",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-contained-update-probe-v1",
            "type": "volume",
        },
        {
            "destination": "/profile/config",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-contained-profile-config-v1",
            "type": "volume",
        },
        {
            "destination": "/runtime",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-runtime",
            "type": "volume",
        },
        {
            "destination": "/seed",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-contained-admitted-v1",
            "type": "volume",
        },
    ]
    expected_tmpfs = {
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
    }
    controls = {
        "cap_drop": ["ALL"],
        "cgroupns_mode": "private",
        "devices": [],
        "ipc_mode": "private",
        "memory_bytes": 805306368,
        "memory_swap_bytes": 805306368,
        "mounts": expected_mounts,
        "nano_cpus": 1000000000,
        "network_mode": "none",
        "no_new_privileges": True,
        "pids_limit": 128,
        "privileged": False,
        "read_only_rootfs": True,
        "runtime": "runc",
        "tmpfs": expected_tmpfs,
        "ulimits": [{"hard": 256, "name": "nofile", "soft": 256}],
        "user": "1000:1000",
        "working_dir": "/profile/workspace",
    }
    if (
        {key: isolation[key] for key in controls} != controls
        or isolation["environment"]
        != {
            "HOME": "/profile/home",
            "NODE_VERSION": "24.16.0",
            "OPENCLAW_CONFIG_PATH": "/profile/config/openclaw.json",
            "OPENCLAW_STATE_DIR": "/profile/state",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "YARN_VERSION": "1.22.22",
        }
    ):
        raise AdmissionEvidenceError("update isolation controls changed")
    docker = environment["docker"]
    os_profile = {
        "image": image,
        "isolation": isolation,
        "server": docker["server"],
    }
    if (
        environment["os_profile_digest"] != canonical_digest(os_profile)
        or environment["os_profile_digest"] != _UPDATE_OS_PROFILE_DIGEST
        or docker["assurance"] != "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"
        or docker["context"]
        != {
            "endpoint": "unix:///Users/yousi/.colima/aragorn-bakeoff/docker.sock",
            "name": "colima-aragorn-bakeoff",
            "skip_tls_verify": False,
            "tls_material_count": 0,
        }
        or docker["server"]["security_options"]
        != ["name=apparmor", "name=cgroupns", "name=seccomp,profile=builtin"]
        or environment["limitations"]
        != [
            "CONTAINER_EXIT_DOES_NOT_ESTABLISH_CROSS_HOST_REPRODUCIBILITY",
            "DOCKER_CONTROL_PLANE_SELF_REPORTED",
            "ENGINE_CONTAINER_AND_HOST_NOT_INDEPENDENTLY_ATTESTED",
            "PLATFORM_MANIFEST_DIGEST_RETAINED_NOT_INDEPENDENTLY_REDERIVED",
        ]
    ):
        raise AdmissionEvidenceError("update environment binding changed")
    if not (
        _time(container["created_at"])
        <= _time(state["started_at"])
        <= _time(probe["runtime"]["version_command"]["started_at"])
        <= _time(probe["recorded_at"])
        <= _time(state["finished_at"])
    ):
        raise AdmissionEvidenceError("update container timing is not causal")


def _verify_live_reload_bindings(
    receipt: Mapping[str, Any],
    probe: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> None:
    if (
        receipt["recorded_at"] != probe["recorded_at"]
        or environment["recorded_at"] != probe["recorded_at"]
    ):
        raise AdmissionEvidenceError("live-reload evidence timestamps differ")
    if receipt["bindings"] != {
        "runtime": {
            "name": "openclaw-contained",
            "version": "2026.7.1",
            "repository_url": "https://github.com/openclaw/openclaw",
            "commit": _OPENCLAW_COMMIT,
            "source_tree_digest": _OPENCLAW_RUNTIME_TREE,
        },
        "adapter": {
            "name": "openclaw-contained-live-reload-slice",
            "implementation_digest": _LIVE_IMPLEMENTATION_DIGEST,
            "configuration_digest": _LIVE_CONFIG_DIGEST,
        },
        "environment": {
            "worker_digest": _OPENCLAW_PLATFORM_MANIFEST,
            "os_profile_digest": _LIVE_OS_PROFILE_DIGEST,
        },
        "aragorn": _ARAGORN_BINDING,
    }:
        raise AdmissionEvidenceError("live-reload receipt bindings changed")
    adapter = probe["adapter"]
    if (
        adapter["configuration_digest"]
        != canonical_digest(adapter["configuration"])
        or adapter["configuration_digest"] != _LIVE_CONFIG_DIGEST
        or adapter["implementation_digest"] != _LIVE_IMPLEMENTATION_DIGEST
    ):
        raise AdmissionEvidenceError("live-reload adapter binding changed")


def _live_request(source: str) -> dict[str, Any]:
    return {
        "openclawVersion": "2026.7.1",
        "origin": {"spec": source, "type": "path"},
        "protocolVersion": 1,
        "request": {
            "kind": "skill-install",
            "mode": "update",
            "requestedSpecifier": source,
        },
        "skill": {"installId": "path"},
        "source": {
            "authority": "user",
            "kind": "local-path",
            "mutable": True,
            "network": False,
        },
        "sourcePath": source,
        "sourcePathKind": "directory",
        "targetName": "aragorn-admitted",
        "targetType": "skill",
    }


def _expected_live_configuration() -> dict[str, Any]:
    return {
        "agents": {
            "defaults": {
                "skills": ["aragorn-admitted"],
                "workspace": "/profile/workspace",
            },
            "list": [
                {
                    "id": "main",
                    "skills": ["aragorn-admitted"],
                    "workspace": "/profile/workspace",
                }
            ],
        },
        "plugins": {"enabled": False},
        "security": {
            "installPolicy": {
                "enabled": True,
                "exec": {
                    "args": ["/probe/live-reload-probe.mjs", "policy"],
                    "command": "/usr/local/bin/node",
                    "maxOutputBytes": 4096,
                    "noOutputTimeoutMs": 5000,
                    "source": "exec",
                    "timeoutMs": 5000,
                    "trustedDirs": ["/probe", "/usr/local/bin"],
                },
                "targets": ["skill"],
            }
        },
        "skills": {
            "load": {
                "allowSymlinkTargets": [],
                "extraDirs": [],
                "watch": True,
                "watchDebounceMs": 250,
            }
        },
    }


def _verify_live_reload_probe(probe: Mapping[str, Any]) -> None:
    if (
        probe["decision"]
        != {"installer_work_eligible": False, "status": "NOT_TESTED"}
        or probe["limitations"]
        != [
            "ONLY_LOCAL_DIRECTORY_GLOBAL_FORCE_REPLACEMENT_EXECUTED",
            "ONLY_FILESYSTEM_WATCH_EXISTING_CHAT_SESSION_SNAPSHOT_EXECUTED",
            "NORMAL_TURNS_INTENTIONALLY_FAIL_WITHOUT_PROVIDER_CREDENTIALS",
            "OTHER_UPDATE_RELOAD_PATHS_REMAIN_NOT_TESTED",
            "CONTAINED_DOCKER_ENVIRONMENT_NOT_INDEPENDENTLY_ATTESTED",
        ]
    ):
        raise AdmissionEvidenceError("live-reload claim boundary changed")
    expected_config = _expected_live_configuration()
    fixtures = {
        "allowed": {
            "digest": (
                "sha256:"
                "494a4ff4168c662b56bf481ada6b17058d75784f99c1c7a7d5fdbe1e9bd0ff63"
            ),
            "directory_mode": "555",
            "file_mode": "444",
            "path": "/sources/allowed-source",
        },
        "blocked": {
            "digest": (
                "sha256:"
                "1b5be1aa3634ebf3e9e803f73706ed4dc0f906d2dece54eda7ef1219356533c0"
            ),
            "directory_mode": "555",
            "file_mode": "444",
            "path": "/sources/blocked-source",
        },
        "seed": {
            "digest": _ADMITTED_DIGEST,
            "directory_mode": "755",
            "file_mode": "644",
            "path": "/profile/state/skills/aragorn-admitted",
        },
    }
    adapter = probe["adapter"]
    runtime = probe["runtime"]
    version = runtime["version_command"]
    if (
        adapter["configuration"] != expected_config
        or adapter["fixtures"] != fixtures
        or runtime["commit"] != _OPENCLAW_COMMIT
        or runtime["name"] != "openclaw-contained"
        or runtime["version"] != "2026.7.1"
        or version["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ]
        or version["exit_code"] != 0
        or version["signal"] is not None
        or version["error"] is not None
        or version["stderr"] != ""
        or version["stdout"] != "OpenClaw 2026.7.1 (2d2ddc4)\n"
    ):
        raise AdmissionEvidenceError("live-reload runtime or fixture identity changed")

    scenarios = probe["scenarios"]
    expected_ids = [
        "ADM-02/update/archive-source-force-replacement",
        "ADM-02/reload/filesystem-watch-invalidation",
        "ADM-02/reload/chat-session-snapshot-consumer",
    ]
    if (
        [item["id"] for item in scenarios] != expected_ids
        or any(item["status"] != "PASS" for item in scenarios)
    ):
        raise AdmissionEvidenceError("live-reload route claims changed")
    update = scenarios[0]["evidence"]
    blocked_command = update["blocked_command"]
    allowed_command = update["allowed_command"]
    command_prefix = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "skills",
        "install",
    ]
    command_suffix = ["--as", "aragorn-admitted", "--force", "--global"]
    if (
        blocked_command["argv"]
        != command_prefix + ["/sources/blocked-source"] + command_suffix
        or blocked_command["exit_code"] != 1
        or blocked_command["error"] is not None
        or blocked_command["signal"] is not None
        or allowed_command["argv"]
        != command_prefix + ["/sources/allowed-source"] + command_suffix
        or allowed_command["exit_code"] != 0
        or allowed_command["error"] is not None
        or allowed_command["signal"] is not None
        or update["target_before_block"] != update["target_after_block"]
    ):
        raise AdmissionEvidenceError("live-reload update transition changed")
    expected_seed = [
        {
            "mode": "755",
            "path": ".",
            "size": 60,
            "type": "directory",
        },
        {
            "digest": _ADMITTED_DIGEST,
            "mode": "644",
            "path": "SKILL.md",
            "size": 104,
            "type": "file",
        },
    ]
    target = update["target_after_allowed"]
    allowed_digest = fixtures["allowed"]["digest"]
    if (
        update["target_before_block"] != expected_seed
        or target["valid"] is not True
        or [item["path"] for item in target["snapshot"]]
        != [".", ".openclaw", ".openclaw/source-origin.json", "SKILL.md"]
        or target["snapshot"][-1]["digest"] != allowed_digest
        or target["origin"]["source"] != "path"
        or target["origin"]["spec"] != "/sources/allowed-source"
        or target["origin"]["slug"] != "aragorn-admitted"
        or target["origin"]["version"] != 1
        or not isinstance(target["origin"]["installedAt"], int)
    ):
        raise AdmissionEvidenceError("live-reload allowed target identity changed")
    records = update["policy_records"]
    if len(records) != 2:
        raise AdmissionEvidenceError("live-reload policy record count changed")
    for record, route, source, decision in (
        (records[0], "blocked-source", "/sources/blocked-source", "block"),
        (records[1], "allowed-source", "/sources/allowed-source", "allow"),
    ):
        fixture = fixtures["blocked" if decision == "block" else "allowed"]
        if (
            record["decision"] != decision
            or record["route"] != route
            or record["request"] != _live_request(source)
            or record["source"] != fixture
            or record["oversized"] is not False
            or record["parse_error"] is not None
            or record["protocol_version"] != 1
            or record["input_bytes"] <= 0
        ):
            raise AdmissionEvidenceError(
                "live-reload policy decision or source binding changed"
            )

    reload_evidence = scenarios[1]["evidence"]
    before = reload_evidence["snapshot_before"]
    after = reload_evidence["snapshot_after"]
    expected_before_markers = {
        "allowed": False,
        "blocked": False,
        "seed": True,
    }
    expected_after_markers = {
        "allowed": True,
        "blocked": False,
        "seed": False,
    }
    if (
        reload_evidence["process_before"]
        != {
            "cmdline": ["openclaw-gateway"],
            "pid": 1,
            "start_time_ticks": reload_evidence["process_before"][
                "start_time_ticks"
            ],
        }
        or reload_evidence["process_after"] != reload_evidence["process_before"]
        or not isinstance(
            reload_evidence["process_before"]["start_time_ticks"], str
        )
        or not reload_evidence["process_before"]["start_time_ticks"].isdigit()
        or reload_evidence["gateway_log_before"]["ready_count"] != 1
        or reload_evidence["gateway_log_after"]["ready_count"] != 1
        or reload_evidence["gateway_log_before"]["restart_count"] != 0
        or reload_evidence["gateway_log_after"]["restart_count"] != 0
        or reload_evidence["gateway_log_after"]["path"]
        != reload_evidence["gateway_log_before"]["path"]
        or reload_evidence["gateway_log_after"]["bytes"]
        <= reload_evidence["gateway_log_before"]["bytes"]
        or not 1 <= reload_evidence["retries"] <= 10
        or before["session_id"] != after["session_id"]
        or before["version"] >= after["version"]
        or before["markers"] != expected_before_markers
        or after["markers"] != expected_after_markers
        or before["skill_names"] != ["aragorn-admitted"]
        or after["skill_names"] != ["aragorn-admitted"]
        or before["prompt_storage"] != "promptRef"
        or after["prompt_storage"] != "promptRef"
        or before["prompt_digest"]
        != "sha256:df7b81a0879f2db0f9c81c0866aa1e229064d700fbb54758816c883c4f6eaca8"
        or after["prompt_digest"]
        != "sha256:911e21e4c6ae9f26737475402a2f709675a0c9d47d26e862272c31ec77d4c75f"
        or any(
            snapshot["run_status"] != "failed"
            or snapshot["runtime_ms"] < 0
            or snapshot["started_at"] > snapshot["ended_at"]
            for snapshot in (before, after)
        )
    ):
        raise AdmissionEvidenceError("live-reload watcher or snapshot proof changed")

    consumer = scenarios[2]["evidence"]
    turns = [consumer["v1_turn"], consumer["blocked_turn"], *consumer["reload_turns"]]
    if len(consumer["reload_turns"]) != reload_evidence["retries"]:
        raise AdmissionEvidenceError("live-reload retry evidence is inconsistent")
    expected_runs = [
        "aragorn-live-reload-v1-0",
        "aragorn-live-reload-blocked-0",
        *[
            f"aragorn-live-reload-v2-{index}"
            for index in range(1, len(consumer["reload_turns"]) + 1)
        ],
    ]
    for turn, run_id in zip(turns, expected_runs):
        send = turn["send"]
        wait = turn["wait"]
        if (
            send["response"] != {"runId": run_id, "status": "started"}
            or wait["response"]["runId"] != run_id
            or wait["response"]["status"] != "ok"
            or not isinstance(wait["response"]["endedAt"], int)
            or send["command"]["exit_code"] != 0
            or wait["command"]["exit_code"] != 0
            or send["command"]["error"] is not None
            or wait["command"]["error"] is not None
            or send["command"]["signal"] is not None
            or wait["command"]["signal"] is not None
            or send["command"]["argv"][2:5] != ["gateway", "call", "chat.send"]
            or wait["command"]["argv"][2:5] != ["gateway", "call", "agent.wait"]
        ):
            raise AdmissionEvidenceError("live-reload session turn proof changed")
    if not (
        _time(version["started_at"])
        <= _time(version["completed_at"])
        <= _time(probe["gateway"]["readiness_command"]["started_at"])
        <= _time(probe["gateway"]["readiness_command"]["completed_at"])
        <= _time(turns[0]["send"]["command"]["started_at"])
        <= _time(turns[0]["wait"]["command"]["completed_at"])
        <= _time(blocked_command["started_at"])
        <= _time(blocked_command["completed_at"])
        <= _time(turns[1]["send"]["command"]["started_at"])
        <= _time(turns[1]["wait"]["command"]["completed_at"])
        <= _time(allowed_command["started_at"])
        <= _time(allowed_command["completed_at"])
        <= _time(turns[2]["send"]["command"]["started_at"])
        <= _time(turns[-1]["wait"]["command"]["completed_at"])
        <= _time(probe["recorded_at"])
    ):
        raise AdmissionEvidenceError("live-reload execution timing is not causal")


def _verify_live_reload_environment(
    probe: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> None:
    container = environment["container"]
    execution = container["probe_exec"]
    state = container["state"]
    image = container["image"]
    expected_image = {
        "id": (
            "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
        ),
        "index_digest": (
            "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
        ),
        "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
        "platform_manifest_digest": _OPENCLAW_PLATFORM_MANIFEST,
        "reference": (
            "node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
        ),
    }
    startup = [
        "/bin/sh",
        "-c",
        "mkdir -p /profile/state/skills && cp -R /seed/. "
        "/profile/state/skills/ && chmod -R u+rwX /profile/state/skills && "
        "exec /usr/local/bin/node "
        "/runtime/lib/node_modules/openclaw/openclaw.mjs gateway run "
        "--allow-unconfigured --auth token --bind loopback --port 18789 "
        "--tailscale off --ws-log full",
    ]
    if (
        environment["recorded_at"] != probe["recorded_at"]
        or image != expected_image
        or container["command"] != startup
        or container["name"] != "aragorn-openclaw-contained-live-reload-v1"
        or container["working_dir"] != "/profile/workspace"
        or execution["exit_code"] != 0
        or execution["mode"] != "docker-exec-shell-capture"
        or execution["recorded_at"] != probe["recorded_at"]
        or execution["target_command"]
        != ["/usr/local/bin/node", "/probe/live-reload-probe.mjs"]
        or execution["stdout"]
        != {"bytes": 12780, "digest": _LIVE_PROBE_DIGEST}
        or execution["user"] != "1000:1000"
        or state["status"] != "exited"
        or state["exit_code"] != 0
        or state["running"]
        or state["paused"]
        or state["restarting"]
        or state["oom_killed"]
        or state["dead"]
        or state["error"] != ""
    ):
        raise AdmissionEvidenceError("live-reload container execution changed")
    expected_mounts = [
        {
            "destination": "/probe",
            "read_only": True,
            "source": (
                "aragorn-openclaw-2026-7-1-contained-live-reload-probe-v1"
            ),
            "type": "volume",
        },
        {
            "destination": "/profile/config",
            "read_only": True,
            "source": (
                "aragorn-openclaw-2026-7-1-contained-live-reload-config-v1"
            ),
            "type": "volume",
        },
        {
            "destination": "/profile/home/.agents",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-contained-guard-v1",
            "type": "volume",
        },
        {
            "destination": "/profile/state/plugin-skills",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-contained-guard-v1",
            "type": "volume",
        },
        {
            "destination": "/profile/workspace/.agents",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-contained-guard-v1",
            "type": "volume",
        },
        {
            "destination": "/profile/workspace/skills",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-contained-guard-v1",
            "type": "volume",
        },
        {
            "destination": "/runtime",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-runtime",
            "type": "volume",
        },
        {
            "destination": "/seed",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-contained-admitted-v1",
            "type": "volume",
        },
        {
            "destination": "/sources",
            "read_only": True,
            "source": (
                "aragorn-openclaw-2026-7-1-contained-live-reload-source-v1"
            ),
            "type": "volume",
        },
    ]
    expected_tmpfs = {
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
    }
    isolation = environment["isolation"]
    controls = {
        "cap_drop": ["ALL"],
        "cgroupns_mode": "private",
        "devices": [],
        "ipc_mode": "private",
        "memory_bytes": 1_073_741_824,
        "memory_swap_bytes": 1_073_741_824,
        "mounts": expected_mounts,
        "nano_cpus": 1_000_000_000,
        "network_mode": "none",
        "no_new_privileges": True,
        "pids_limit": 128,
        "privileged": False,
        "read_only_rootfs": True,
        "runtime": "runc",
        "tmpfs": expected_tmpfs,
        "ulimits": [{"hard": 256, "name": "nofile", "soft": 256}],
        "user": "1000:1000",
        "working_dir": "/profile/workspace",
    }
    if (
        {key: isolation[key] for key in controls} != controls
        or isolation["environment"]
        != {
            "HOME": "/profile/home",
            "NODE_VERSION": "24.16.0",
            "OPENCLAW_CONFIG_PATH": "/profile/config/openclaw.json",
            "OPENCLAW_GATEWAY_TOKEN": (
                "aragorn-contained-live-reload-token-v1"
            ),
            "OPENCLAW_STATE_DIR": "/profile/state",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "YARN_VERSION": "1.22.22",
        }
        or any(
            item["destination"] == "/profile/state/skills"
            for item in isolation["mounts"]
        )
    ):
        raise AdmissionEvidenceError("live-reload isolation controls changed")
    docker = environment["docker"]
    os_profile = {
        "image": image,
        "isolation": isolation,
        "server": docker["server"],
    }
    if (
        environment["os_profile_digest"] != canonical_digest(os_profile)
        or environment["os_profile_digest"] != _LIVE_OS_PROFILE_DIGEST
        or docker["assurance"] != "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"
        or docker["context"]
        != {
            "endpoint": "unix:///Users/yousi/.colima/aragorn-bakeoff/docker.sock",
            "name": "colima-aragorn-bakeoff",
            "skip_tls_verify": False,
            "tls_material_count": 0,
        }
        or docker["server"]["security_options"]
        != ["name=apparmor", "name=cgroupns", "name=seccomp,profile=builtin"]
        or environment["limitations"]
        != [
            "CONTAINER_EXIT_DOES_NOT_ESTABLISH_CROSS_HOST_REPRODUCIBILITY",
            "DOCKER_CONTROL_PLANE_SELF_REPORTED",
            "ENGINE_CONTAINER_AND_HOST_NOT_INDEPENDENTLY_ATTESTED",
            "PLATFORM_MANIFEST_DIGEST_RETAINED_NOT_INDEPENDENTLY_REDERIVED",
        ]
    ):
        raise AdmissionEvidenceError("live-reload environment binding changed")
    if not (
        _time(container["created_at"])
        <= _time(state["started_at"])
        <= _time(probe["runtime"]["version_command"]["started_at"])
        <= _time(probe["recorded_at"])
        <= _time(state["finished_at"])
    ):
        raise AdmissionEvidenceError("live-reload container timing is not causal")


def _verify_config_activation_bindings(
    receipt: Mapping[str, Any],
    probe: Mapping[str, Any],
    environment: Mapping[str, Any],
    prior: Mapping[str, Any],
) -> None:
    if (
        receipt["recorded_at"] != probe["recorded_at"]
        or environment["recorded_at"] != probe["recorded_at"]
    ):
        raise AdmissionEvidenceError("config-activation evidence timestamps differ")
    if receipt["bindings"] != {
        "runtime": {
            "name": "openclaw-contained",
            "version": "2026.7.1",
            "repository_url": "https://github.com/openclaw/openclaw",
            "commit": _OPENCLAW_COMMIT,
            "source_tree_digest": _OPENCLAW_RUNTIME_TREE,
        },
        "adapter": {
            "name": "openclaw-contained-config-activation-slice",
            "implementation_digest": _CONFIG_IMPLEMENTATION_DIGEST,
            "configuration_digest": _LIVE_CONFIG_DIGEST,
        },
        "environment": {
            "worker_digest": _OPENCLAW_PLATFORM_MANIFEST,
            "os_profile_digest": _CONFIG_OS_PROFILE_DIGEST,
        },
        "aragorn": _ARAGORN_BINDING,
    }:
        raise AdmissionEvidenceError("config-activation receipt bindings changed")

    adapter = probe["adapter"]
    fixture = adapter["fixture"]
    if (
        adapter["configuration"] != _expected_live_configuration()
        or adapter["configuration_digest"] != canonical_digest(adapter["configuration"])
        or adapter["configuration_digest"] != _LIVE_CONFIG_DIGEST
        or adapter["implementation_digest"] != _CONFIG_IMPLEMENTATION_DIGEST
        or adapter["writable_configuration_path"] != "/profile/state/openclaw.json"
        or fixture
        != {
            "admission_evidence_digest": _CONFIG_PRIOR_ADMISSION_DIGEST,
            "digest": _ADMITTED_DIGEST,
            "mount": "/profile/state/skills",
            "path": "/profile/state/skills/aragorn-admitted",
            "source_volume": ("aragorn-openclaw-2026-7-1-contained-admitted-v1"),
        }
    ):
        raise AdmissionEvidenceError("config-activation adapter binding changed")

    prior_runtime = prior["runtime"]
    prior_scenarios = {item["id"]: item for item in prior["scenarios"]}
    exact = prior_scenarios.get("ADM-01/exact-admitted-bytes")
    managed = [
        item for item in prior["profile"]["protected_roots"] if item["id"] == "managed"
    ]
    if (
        prior_runtime["name"] != "openclaw-contained"
        or prior_runtime["version"] != "2026.7.1"
        or prior_runtime["commit"] != _OPENCLAW_COMMIT
        or prior_runtime["runtime_tree"]["tree_digest"] != _OPENCLAW_RUNTIME_TREE
        or prior["profile"]["admitted"]
        != {
            "digest": _ADMITTED_DIGEST,
            "path": "/profile/state/skills/aragorn-admitted/SKILL.md",
        }
        or managed
        != [
            {
                "discovery": "/profile/state/skills",
                "discovery_realpath": "/profile/state/skills",
                "id": "managed",
                "mount": "/profile/state/skills",
                "mount_realpath": "/profile/state/skills",
            }
        ]
        or exact is None
        or exact["status"] != "PASS"
        or exact["evidence"]["admitted_digest"] != _ADMITTED_DIGEST
        or exact["evidence"]["initial"]["filePath"]
        != "/profile/state/skills/aragorn-admitted/SKILL.md"
        or exact["evidence"]["final"] != exact["evidence"]["initial"]
    ):
        raise AdmissionEvidenceError("prior exact-admission lineage changed")


def _verify_successful_config_command(
    command: Mapping[str, Any],
    expected_argv: list[str],
) -> None:
    empty_digest = (
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    if (
        command["argv"] != expected_argv
        or command["exit_code"] != 0
        or command["signal"] is not None
        or command["error"] is not None
        or not isinstance(command["pid"], int)
        or command["pid"] <= 1
        or command["stderr_bytes"] != 0
        or command["stderr_digest"] != empty_digest
        or not isinstance(command["stdout_bytes"], int)
        or command["stdout_bytes"] <= 0
        or not isinstance(command["stdout_digest"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", command["stdout_digest"]) is None
        or _time(command["started_at"]) > _time(command["completed_at"])
    ):
        raise AdmissionEvidenceError("config-activation RPC evidence changed")


def _verify_config_snapshot(
    snapshot: Mapping[str, Any],
    enabled: Any,
    command: Any,
) -> None:
    expected = _expected_live_configuration()
    if enabled is not None:
        expected = {
            **expected,
            "skills": {
                **expected["skills"],
                "entries": {"aragorn-admitted": {"enabled": enabled}},
            },
        }
    document = snapshot["document"]
    configuration = {key: value for key, value in document.items() if key != "meta"}
    expected_identity = {
        None: {
            "digest": (
                "sha256:ec9e0767ee946f7454d753e294b05b6f"
                "6924d8d933eae4585dd0739ac075ba09"
            ),
            "size": 576,
        },
        False: {
            "digest": (
                "sha256:165a57a11fef082cd785ac5caebfe0b24"
                "c793236ccf8b1f5317f795c0c8acce4"
            ),
            "size": 1150,
        },
        True: {
            "digest": (
                "sha256:9b1a29ebe95146b6b89600e05e439e124"
                "641a3ac5410876b95b35272bb705612"
            ),
            "size": 1149,
        },
    }[enabled]
    if (
        configuration != expected
        or snapshot["path"] != "/profile/state/openclaw.json"
        or snapshot["mode"] != "600"
        or {
            "digest": snapshot["digest"],
            "size": snapshot["size"],
        }
        != expected_identity
    ):
        raise AdmissionEvidenceError("persisted config identity changed")
    if enabled is None:
        if "meta" in document or command is not None:
            raise AdmissionEvidenceError("initial config metadata changed")
        return
    meta = document["meta"]
    if (
        set(meta) != {"lastTouchedAt", "lastTouchedVersion"}
        or meta["lastTouchedVersion"] != "2026.7.1"
        or command is None
        or not (
            _time(command["started_at"])
            <= _time(meta["lastTouchedAt"])
            <= _time(command["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("persisted config metadata changed")


def _verify_config_turn(
    turn: Mapping[str, Any],
    label: str,
    attempt: int,
) -> None:
    run_id = f"aragorn-config-activation-{label}-{attempt}"
    send_params = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": f"Inert config-activation probe turn {label} {attempt}.",
        "sessionKey": "agent:main:aragorn-config-activation-v1",
        "timeoutMs": 5000,
    }
    wait_params = {"runId": run_id, "timeoutMs": 10000}
    prefix = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
    ]
    send = turn["send"]
    wait = turn["wait"]
    _verify_successful_config_command(
        send["command"],
        prefix
        + [
            "chat.send",
            "--json",
            "--timeout",
            "5000",
            "--params",
            json.dumps(send_params, separators=(",", ":"), sort_keys=True),
        ],
    )
    _verify_successful_config_command(
        wait["command"],
        prefix
        + [
            "agent.wait",
            "--json",
            "--timeout",
            "12000",
            "--params",
            json.dumps(wait_params, separators=(",", ":"), sort_keys=True),
        ],
    )
    if (
        send["response"] != {"runId": run_id, "status": "started"}
        or wait["response"]["runId"] != run_id
        or wait["response"]["status"] != "ok"
        or not isinstance(wait["response"]["endedAt"], int)
        or _time(send["command"]["completed_at"]) > _time(wait["command"]["started_at"])
    ):
        raise AdmissionEvidenceError("config-activation turn evidence changed")


def _verify_config_snapshot_state(
    snapshot: Mapping[str, Any],
    *,
    enabled: bool,
) -> None:
    expected = (
        {
            "marker_present": True,
            "prompt_bytes": 698,
            "prompt_digest": (
                "sha256:df7b81a0879f2db0f9c81c0866aa1e22"
                "9064d700fbb54758816c883c4f6eaca8"
            ),
            "prompt_storage": "promptRef",
            "skill_names": ["aragorn-admitted"],
        }
        if enabled
        else {
            "marker_present": False,
            "prompt_bytes": 0,
            "prompt_digest": (
                "sha256:e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855"
            ),
            "prompt_storage": "inline",
            "skill_names": [],
        }
    )
    if (
        {key: snapshot[key] for key in expected} != expected
        or snapshot["run_status"] != "failed"
        or not isinstance(snapshot["session_id"], str)
        or not snapshot["session_id"]
        or not isinstance(snapshot["version"], int)
        or snapshot["version"] < 0
        or not isinstance(snapshot["started_at"], int)
        or not isinstance(snapshot["ended_at"], int)
        or snapshot["started_at"] > snapshot["ended_at"]
        or not isinstance(snapshot["runtime_ms"], int)
        or snapshot["runtime_ms"] < 0
    ):
        raise AdmissionEvidenceError("config-activation session snapshot changed")


def _verify_config_activation_probe(probe: Mapping[str, Any]) -> None:
    if probe["decision"] != {
        "installer_work_eligible": False,
        "status": "NOT_TESTED",
    } or probe["limitations"] != [
        "ONLY_CONFIG_ENTRY_ENABLE_DISABLE_EXECUTED",
        "ONLY_CONFIG_INVALIDATION_EXISTING_CHAT_SESSION_EXECUTED",
        "NORMAL_TURNS_INTENTIONALLY_FAIL_WITHOUT_PROVIDER_CREDENTIALS",
        "CONFIGURATION_COPY_WRITABLE_TO_UNPRIVILEGED_RUNTIME_UID",
        "ADMITTED_SKILL_ROOT_READ_ONLY_VOLUME",
        "OTHER_UPDATE_RELOAD_PATHS_REMAIN_NOT_TESTED",
        "CONTAINED_DOCKER_ENVIRONMENT_NOT_INDEPENDENTLY_ATTESTED",
    ]:
        raise AdmissionEvidenceError("config-activation claim boundary changed")

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
        runtime["commit"] != _OPENCLAW_COMMIT
        or runtime["name"] != "openclaw-contained"
        or runtime["version"] != "2026.7.1"
        or version["stdout_bytes"] != 28
        or version["stdout_digest"]
        != "sha256:9e98975ff3973bcd88f224e1820a177c3c881f7a46b51b7dc5ec5d050f72607f"
    ):
        raise AdmissionEvidenceError("config-activation runtime identity changed")

    gateway = probe["gateway"]
    _verify_successful_config_command(
        gateway["command"],
        [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            "system.info",
            "--json",
            "--timeout",
            "5000",
        ],
    )
    if any(
        gateway["info"][key] != value
        for key, value in {
            "arch": "arm64",
            "nodeVersion": "v24.16.0",
            "pid": 1,
            "platform": "linux",
            "port": 18789,
        }.items()
    ):
        raise AdmissionEvidenceError("config-activation Gateway identity changed")

    scenarios = probe["scenarios"]
    if [(item["id"], item["status"]) for item in scenarios] != [
        ("ADM-02/update/config-entry-activation", "PASS"),
        ("ADM-02/reload/config-invalidation", "PASS"),
    ]:
        raise AdmissionEvidenceError("config-activation route claims changed")

    update = scenarios[0]["evidence"]
    disable = update["disable"]
    enable = update["enable"]
    prefix = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "skills.update",
        "--json",
        "--timeout",
        "5000",
        "--params",
    ]
    for action, enabled in ((disable, False), (enable, True)):
        params = {"enabled": enabled, "skillKey": "aragorn-admitted"}
        _verify_successful_config_command(
            action["command"],
            prefix + [json.dumps(params, separators=(",", ":"), sort_keys=True)],
        )
        if action["params"] != params or action["response"] != {
            "config": {"enabled": enabled},
            "ok": True,
            "skillKey": "aragorn-admitted",
        }:
            raise AdmissionEvidenceError("config activation RPC result changed")

    status_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "skills.status",
        "--json",
        "--timeout",
        "5000",
    ]
    active = {
        "blocked_by_agent_filter": False,
        "disabled": False,
        "eligible": True,
        "model_visible": True,
        "source": "openclaw-managed",
        "user_invocable": True,
    }
    disabled = {
        **active,
        "disabled": True,
        "eligible": False,
        "model_visible": False,
    }
    for label, expected in (
        ("initial_status", active),
        ("disabled_status", disabled),
        ("enabled_status", active),
    ):
        _verify_successful_config_command(update[label]["command"], status_argv)
        if update[label]["skill"] != expected:
            raise AdmissionEvidenceError("config activation status changed")

    _verify_config_snapshot(update["config_before"], None, None)
    _verify_config_snapshot(update["config_after_disable"], False, disable["command"])
    _verify_config_snapshot(update["config_after_enable"], True, enable["command"])
    expected_target = [
        {
            "mode": "555",
            "path": ".",
            "size": 4096,
            "type": "directory",
        },
        {
            "digest": _ADMITTED_DIGEST,
            "mode": "444",
            "path": "SKILL.md",
            "size": 104,
            "type": "file",
        },
    ]
    if (
        update["policy_record_count_before"] != 0
        or update["policy_record_count_after"] != 0
        or update["target_before"] != expected_target
        or update["target_after"] != expected_target
        or update["write_guard"]["blocked"] is not True
        or update["write_guard"]["code"] not in {"EACCES", "EROFS"}
    ):
        raise AdmissionEvidenceError("read-only admitted target identity changed")

    reload_evidence = scenarios[1]["evidence"]
    initial = reload_evidence["initial_snapshot"]
    disabled_snapshot = reload_evidence["disabled"]["snapshot"]
    enabled_snapshot = reload_evidence["enabled"]["snapshot"]
    _verify_config_snapshot_state(initial, enabled=True)
    _verify_config_snapshot_state(disabled_snapshot, enabled=False)
    _verify_config_snapshot_state(enabled_snapshot, enabled=True)
    if len(
        {
            initial["session_id"],
            disabled_snapshot["session_id"],
            enabled_snapshot["session_id"],
        }
    ) != 1 or not (
        initial["version"] < disabled_snapshot["version"] < enabled_snapshot["version"]
    ):
        raise AdmissionEvidenceError("config invalidation session lineage changed")

    _verify_config_turn(reload_evidence["initial_turn"], "initial", 0)
    for label in ("disabled", "enabled"):
        turns = reload_evidence[label]["turns"]
        if not 1 <= len(turns) <= 10:
            raise AdmissionEvidenceError("config invalidation retry bound changed")
        for attempt, turn in enumerate(turns, 1):
            _verify_config_turn(turn, label, attempt)

    process = {
        "cmdline": ["openclaw-gateway"],
        "pid": 1,
        "start_time_ticks": reload_evidence["process_before"]["start_time_ticks"],
    }
    before_log = reload_evidence["gateway_log_before"]
    after_log = reload_evidence["gateway_log_after"]
    if (
        not isinstance(process["start_time_ticks"], str)
        or not process["start_time_ticks"].isdigit()
        or reload_evidence["process_before"] != process
        or reload_evidence["process_after"] != process
        or before_log["ready_count"] != 1
        or after_log["ready_count"] != 1
        or before_log["restart_count"] != 0
        or after_log["restart_count"] != 0
        or before_log["path"] != after_log["path"]
        or after_log["bytes"] <= before_log["bytes"]
    ):
        raise AdmissionEvidenceError("config invalidation process identity changed")

    initial_turn = reload_evidence["initial_turn"]
    disabled_turns = reload_evidence["disabled"]["turns"]
    enabled_turns = reload_evidence["enabled"]["turns"]
    if not (
        _time(version["started_at"])
        <= _time(version["completed_at"])
        <= _time(gateway["command"]["started_at"])
        <= _time(gateway["command"]["completed_at"])
        <= _time(initial_turn["send"]["command"]["started_at"])
        <= _time(initial_turn["wait"]["command"]["completed_at"])
        <= _time(update["initial_status"]["command"]["started_at"])
        <= _time(update["initial_status"]["command"]["completed_at"])
        <= _time(disable["command"]["started_at"])
        <= _time(disable["command"]["completed_at"])
        <= _time(disabled_turns[0]["send"]["command"]["started_at"])
        <= _time(disabled_turns[-1]["wait"]["command"]["completed_at"])
        <= _time(update["disabled_status"]["command"]["started_at"])
        <= _time(update["disabled_status"]["command"]["completed_at"])
        <= _time(enable["command"]["started_at"])
        <= _time(enable["command"]["completed_at"])
        <= _time(enabled_turns[0]["send"]["command"]["started_at"])
        <= _time(enabled_turns[-1]["wait"]["command"]["completed_at"])
        <= _time(update["enabled_status"]["command"]["started_at"])
        <= _time(update["enabled_status"]["command"]["completed_at"])
        <= _time(probe["recorded_at"])
    ):
        raise AdmissionEvidenceError("config-activation timing is not causal")


def _verify_config_activation_environment(
    probe: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> None:
    container = environment["container"]
    state = container["state"]
    execution = container["probe_exec"]
    image = container["image"]
    expected_image = {
        "id": (
            "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
        ),
        "index_digest": (
            "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
        ),
        "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
        "platform_manifest_digest": _OPENCLAW_PLATFORM_MANIFEST,
        "reference": (
            "node@sha256:242549cd46785b480c832479a730f4f2"
            "a20865d61ea2e404fdb2a5c3d3b73ecf"
        ),
    }
    startup = [
        "/bin/sh",
        "-c",
        "cp /profile/config/openclaw.json /profile/state/openclaw.json && "
        "chmod 0600 /profile/state/openclaw.json && exec /usr/local/bin/node "
        "/runtime/lib/node_modules/openclaw/openclaw.mjs gateway run "
        "--allow-unconfigured --auth token --bind loopback --port 18789 "
        "--tailscale off --ws-log full",
    ]
    probe_raw = _canonical_bytes(probe) + b"\n"
    if (
        environment["recorded_at"] != probe["recorded_at"]
        or image != expected_image
        or container["command"] != startup
        or container["name"] != "aragorn-openclaw-contained-config-activation-v1"
        or container["working_dir"] != "/profile/workspace"
        or execution
        != {
            "command": [
                "/usr/local/bin/node",
                "/config-probe/config-activation-probe.mjs",
            ],
            "exit_code": 0,
            "mode": "docker-exec-stdout-capture",
            "recorded_at": probe["recorded_at"],
            "stdout": {
                "bytes": len(probe_raw),
                "digest": _line_digest(probe),
            },
            "target_command": [
                "/usr/local/bin/node",
                "/config-probe/config-activation-probe.mjs",
            ],
            "user": "1000:1000",
        }
        or state["status"] != "exited"
        or state["exit_code"] != 0
        or state["running"]
        or state["paused"]
        or state["restarting"]
        or state["restart_count"] != 0
        or state["oom_killed"]
        or state["dead"]
        or state["error"] != ""
        or re.fullmatch(r"[0-9a-f]{64}", container["id"]) is None
        or probe["gateway"]["info"]["hostname"] != container["id"][:12]
        or probe["gateway"]["info"]["machineName"] != container["id"][:12]
    ):
        raise AdmissionEvidenceError("config-activation container execution changed")

    expected_mounts = [
        {
            "destination": "/config-probe",
            "read_only": True,
            "source": (
                "aragorn-openclaw-2026-7-1-contained-config-activation-probe-v1"
            ),
            "type": "volume",
        },
        {
            "destination": "/probe",
            "read_only": True,
            "source": ("aragorn-openclaw-2026-7-1-contained-live-reload-probe-v1"),
            "type": "volume",
        },
        {
            "destination": "/profile/config",
            "read_only": True,
            "source": ("aragorn-openclaw-2026-7-1-contained-live-reload-config-v1"),
            "type": "volume",
        },
        {
            "destination": "/profile/home/.agents",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-contained-guard-v1",
            "type": "volume",
        },
        {
            "destination": "/profile/state/plugin-skills",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-contained-guard-v1",
            "type": "volume",
        },
        {
            "destination": "/profile/state/skills",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-contained-admitted-v1",
            "type": "volume",
        },
        {
            "destination": "/profile/workspace/.agents",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-contained-guard-v1",
            "type": "volume",
        },
        {
            "destination": "/profile/workspace/skills",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-contained-guard-v1",
            "type": "volume",
        },
        {
            "destination": "/runtime",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-runtime",
            "type": "volume",
        },
    ]
    expected_tmpfs = {
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
    }
    isolation = environment["isolation"]
    controls = {
        "cap_drop": ["ALL"],
        "cgroupns_mode": "private",
        "devices": [],
        "ipc_mode": "private",
        "memory_bytes": 1_073_741_824,
        "memory_swap_bytes": 1_073_741_824,
        "mounts": expected_mounts,
        "nano_cpus": 1_000_000_000,
        "network_mode": "none",
        "no_new_privileges": True,
        "pids_limit": 128,
        "privileged": False,
        "read_only_rootfs": True,
        "restart_policy": {"maximum_retry_count": 0, "name": "no"},
        "runtime": "runc",
        "tmpfs": expected_tmpfs,
        "ulimits": [{"hard": 256, "name": "nofile", "soft": 256}],
        "user": "1000:1000",
        "working_dir": "/profile/workspace",
    }
    if (
        {key: isolation[key] for key in controls} != controls
        or isolation["environment"]
        != {
            "HOME": "/profile/home",
            "NODE_VERSION": "24.16.0",
            "OPENCLAW_CONFIG_PATH": "/profile/state/openclaw.json",
            "OPENCLAW_GATEWAY_TOKEN": ("aragorn-contained-live-reload-token-v1"),
            "OPENCLAW_STATE_DIR": "/profile/state",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "YARN_VERSION": "1.22.22",
        }
        or len({item["destination"] for item in isolation["mounts"]})
        != len(expected_mounts)
        or "/profile/state/skills" in isolation["tmpfs"]
    ):
        raise AdmissionEvidenceError("config-activation isolation changed")

    docker = environment["docker"]
    os_profile = {
        "image": image,
        "isolation": isolation,
        "server": docker["server"],
    }
    release = docker["server"]["kernel_version"]
    gateway_info = probe["gateway"]["info"]
    if (
        environment["os_profile_digest"] != canonical_digest(os_profile)
        or environment["os_profile_digest"] != _CONFIG_OS_PROFILE_DIGEST
        or gateway_info["diskPath"] != "/profile/state"
        or gateway_info["release"] != release
        or gateway_info["osLabel"] != f"Linux {release}"
        or docker["assurance"] != "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"
        or docker["context"]
        != {
            "endpoint": "unix:///Users/yousi/.colima/aragorn-bakeoff/docker.sock",
            "name": "colima-aragorn-bakeoff",
            "skip_tls_verify": False,
            "tls_material_count": 0,
        }
        or docker["server"]["security_options"]
        != ["name=apparmor", "name=cgroupns", "name=seccomp,profile=builtin"]
        or environment["limitations"]
        != [
            "CONTAINER_EXIT_DOES_NOT_ESTABLISH_CROSS_HOST_REPRODUCIBILITY",
            "DOCKER_CONTROL_PLANE_SELF_REPORTED",
            "ENGINE_CONTAINER_AND_HOST_NOT_INDEPENDENTLY_ATTESTED",
            "PLATFORM_MANIFEST_DIGEST_RETAINED_NOT_INDEPENDENTLY_REDERIVED",
        ]
    ):
        raise AdmissionEvidenceError("config-activation environment binding changed")
    if not (
        _time(container["created_at"])
        <= _time(state["started_at"])
        <= _time(probe["runtime"]["version_command"]["started_at"])
        <= _time(probe["recorded_at"])
        <= _time(state["finished_at"])
    ):
        raise AdmissionEvidenceError("config-activation container timing is not causal")


def _line_digest(document: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(document) + b"\n").hexdigest()


def _canonical_bytes(document: object) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise AdmissionEvidenceError("timestamp is not a string")
    normalized = _RFC3339_EXTRA_PRECISION.sub(r"\1", value)
    parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise AdmissionEvidenceError("timestamp lacks timezone")
    return parsed


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdmissionEvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AdmissionEvidenceError(f"non-finite JSON value: {value}")
