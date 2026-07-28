"""Semantic verification for retained partial OpenClaw admission claims."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .admission_conformance import (
    AdmissionConformanceError,
    validate_admission_conformance,
)
from .admission_decision import evaluate_admission
from .admission_routes import validate_openclaw_2026_7_1_route_inventory
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

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
_ADMITTED_TEXT = (
    "---\n"
    "name: aragorn-admitted\n"
    "description: Inert contained-profile fixture.\n"
    "---\n"
    "# Aragorn admitted fixture\n"
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
_LIVE_CRON_PROBE_DIGEST = (
    "sha256:18cb9b9ee5f80aad781dc0c495487d198bb8b9601847f7af65b24ea0a073cbc1"
)
_LIVE_CRON_ENV_DIGEST = (
    "sha256:0def31e7877f8de6d6271987e7146073e2f89b85ca7be323665e4938b6b178b9"
)
_LIVE_CRON_EVIDENCE_PAIR = sorted(
    (_LIVE_CRON_ENV_DIGEST, _LIVE_CRON_PROBE_DIGEST)
)
_LIVE_CRON_IMPLEMENTATION_DIGEST = (
    "sha256:9bda8e8446c9307d2320099d0be8f28179f00bd1507035cae76255f0bc0ad8cc"
)
_LIVE_CRON_OS_PROFILE_DIGEST = (
    "sha256:8bb24cceca24b18602b1bafa97ea61ba9ede5abe3980ee7be73e4bb776a41789"
)
_LIVE_CRON_POLL_LIMIT = 20
_CONFIG_PROBE_SCHEMA = "aragorn/openclaw-contained-config-activation-probe-evidence/v1"
_CONFIG_ENV_SCHEMA = (
    "aragorn/openclaw-contained-config-activation-environment-evidence/v1"
)
_CONFIG_PROBE_DIGEST = (
    "sha256:c4da4d5c2fc09b211d3a2174648fca32e225bcbe42c592e2045c7aee5c74c56b"
)
_CONFIG_ENV_DIGEST = (
    "sha256:9136db0c40dc4054b5a77044ccf85070623b04b49b3627f3fbeefe316e81eb0b"
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
    "sha256:4cbc285e65d7cd5e7ec2cea1651578cd93ed64a7a5b96f5e180dd498b488a8fe"
)
_CONFIG_OS_PROFILE_DIGEST = (
    "sha256:cf82ddd73800026ece95e2119079f3f3f31cc934ef699a87880131fc6146ec72"
)
_UPDATE_RELOAD_COVERAGE_SCHEMA = (
    "aragorn/openclaw-update-reload-route-coverage-evidence/v1"
)
_UPDATE_RELOAD_COVERAGE_DIGEST = (
    "sha256:ff2a4a0c83a9c318204cfc5ed812669aa7885c76c05f6d50982f530d5a4af7ef"
)
_UPDATE_RELOAD_INVENTORY_DIGEST = (
    "sha256:c175cd145a0c18d80921edbeb2452e34182188f97ee4e3b8d26176e7e38f5b41"
)
_LIVE_CRON_RECEIPT_DIGEST = (
    "sha256:82d04dbac17f6d3bddf20bb76626be1764aca2c2acf8c4e53a23d6e36e3a9caa"
)
_CONFIG_RECEIPT_DIGEST = (
    "sha256:cabe43b99f6ea301b4f9fe3321b6713ef3a6735ff866539de3b8532d9a586e2f"
)
_UPDATE_RELOAD_SOURCE_RECEIPTS = [
    _LIVE_CRON_RECEIPT_DIGEST,
    _CONFIG_RECEIPT_DIGEST,
]
_PARTIAL_UPDATE_ROUTE = "ADM-02/update/archive-source-force-replacement"
_PARTIAL_UPDATE_OBSERVATION = {
    "executed_variant": "local-directory-cli-force-global",
    "inventory_route_id": _PARTIAL_UPDATE_ROUTE,
    "source_receipt_digest": _LIVE_CRON_RECEIPT_DIGEST,
    "status": "PASS",
    "satisfies_inventory_route": False,
}
_OUTSIDE_UPDATE_RELOAD_COVERAGE_REASON = [
    "SCENARIO_OUTSIDE_UPDATE_RELOAD_COVERAGE_SLICE"
]
_UPDATE_RELOAD_COVERAGE_REASONS = {
    "DET-01/identical-canonical-input-replay": ["IDENTICAL_REPLAY_NOT_TESTED"],
    "ADM-01/exact-admitted-bytes": ["EXACT_ACTIVATED_BYTES_NOT_TESTED"],
    "ADM-02/install": _OUTSIDE_UPDATE_RELOAD_COVERAGE_REASON,
    "ADM-02/update": ["UPDATE_ROUTE_COVERAGE_INCOMPLETE"],
    "ADM-02/direct-write": _OUTSIDE_UPDATE_RELOAD_COVERAGE_REASON,
    "ADM-02/rename": _OUTSIDE_UPDATE_RELOAD_COVERAGE_REASON,
    "ADM-02/symlink": _OUTSIDE_UPDATE_RELOAD_COVERAGE_REASON,
    "ADM-02/auto-discovery": _OUTSIDE_UPDATE_RELOAD_COVERAGE_REASON,
    "ADM-02/reload": ["RELOAD_ROUTE_COVERAGE_INCOMPLETE"],
    "ADM-02/restart": _OUTSIDE_UPDATE_RELOAD_COVERAGE_REASON,
    "ADM-03/policy-failure": _OUTSIDE_UPDATE_RELOAD_COVERAGE_REASON,
    "ADM-03/policy-tampering": _OUTSIDE_UPDATE_RELOAD_COVERAGE_REASON,
}
_MODEL_ACTIVATION_PROBE_SCHEMA = (
    "aragorn/openclaw-contained-model-activation-probe-evidence/v1"
)
_MODEL_ACTIVATION_ENV_SCHEMA = (
    "aragorn/openclaw-contained-model-activation-environment-evidence/v1"
)
_MODEL_ACTIVATION_PROBE_DIGEST = (
    "sha256:0cfe8ebd4130d6194f2d82121218fc1535d0184deeacd030b7df34a1a794338c"
)
_MODEL_ACTIVATION_ENV_DIGEST = (
    "sha256:284b1d05408681185fca4b21c0a5b82a38607f4e2bbf9ff465e305f41c4c5aa4"
)
_MODEL_ACTIVATION_EVIDENCE_SET = sorted(
    (
        _CONFIG_PRIOR_ADMISSION_DIGEST,
        _MODEL_ACTIVATION_ENV_DIGEST,
        _MODEL_ACTIVATION_PROBE_DIGEST,
    )
)
_MODEL_ACTIVATION_IMPLEMENTATION_DIGEST = (
    "sha256:15b7eef1895e1f6ac85c9d944f17069cf680844122d355f1ca8828deaf9b2769"
)
_MODEL_ACTIVATION_CONFIG_DIGEST = (
    "sha256:348f0c7f35bd9b8a267ced01d867fe1a995c8f8fea2458a890bc489fa4589628"
)
_MODEL_ACTIVATION_OS_PROFILE_DIGEST = (
    "sha256:176f991818f585f71e37d21cf5b877230182c1d45d100a0cd9c4426adb8ed3bb"
)
_MODEL_ACTIVATION_VERSION_STDOUT_BYTES = 28
_MODEL_ACTIVATION_TARGET_ENTRY_COUNT = 2
_MODEL_ACTIVATION_REQUEST_COUNT = 2
_MODEL_ACTIVATION_SCENARIO = "ADM-01/exact-admitted-bytes"
_MODEL_ACTIVATION_STATUSES = {
    key: "PASS" if key == _MODEL_ACTIVATION_SCENARIO else "NOT_TESTED"
    for key in _STATUSES
}
_MODEL_ACTIVATION_REASONS = {
    key: (
        ["IDENTICAL_REPLAY_NOT_TESTED"]
        if key == "DET-01/identical-canonical-input-replay"
        else ["SCENARIO_OUTSIDE_MODEL_ACTIVATION_SLICE"]
    )
    for key in _STATUSES
    if key != _MODEL_ACTIVATION_SCENARIO
}
_OPENCLAW_COMMIT = "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4"
_OPENCLAW_RUNTIME_TREE = (
    "sha256:475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c"
)
_OPENCLAW_PLATFORM_MANIFEST = (
    "sha256:1df790a7d590f617d0d3c2cd84cbe18b5400ff972dd9701670f7e5a4f1634e52"
)
_DETERMINISTIC_VECTOR_SCHEMA = "aragorn/admission-authority-vector-set/v1"
_DETERMINISTIC_REPLAY_SCHEMA = "aragorn/admission-authority-replay-evidence/v1"
_DETERMINISTIC_VECTOR_DIGEST = (
    "sha256:1b611972663a9de166bc4de16e15bf4a05841a3dc895cc920e71094b55a16161"
)
_DETERMINISTIC_REPLAY_DIGEST = (
    "sha256:324acb5363d23aef73addc3689416f0bba730ae32b90410c7d1670999ddc9c1f"
)
_DETERMINISTIC_EVIDENCE_SET = sorted(
    (_DETERMINISTIC_REPLAY_DIGEST, _DETERMINISTIC_VECTOR_DIGEST)
)
_DETERMINISTIC_SCENARIO = "DET-01/identical-canonical-input-replay"
_DETERMINISTIC_STATUSES = {
    key: "PASS" if key == _DETERMINISTIC_SCENARIO else "NOT_TESTED"
    for key in _STATUSES
}
_DETERMINISTIC_REASON = ["SCENARIO_OUTSIDE_DETERMINISTIC_REPLAY_SLICE"]
_DETERMINISTIC_REASONS = {
    key: _DETERMINISTIC_REASON
    for key in _STATUSES
    if key != _DETERMINISTIC_SCENARIO
}
_DETERMINISTIC_CASES = ("allow", "deny", "error", "review")
_DETERMINISTIC_SEEDS = ("1", "2", "3")
_DETERMINISTIC_EXPECTED = {
    "allow": {"reason_codes": [], "verdict": "ALLOW"},
    "deny": {"reason_codes": ["TEST_HARD_DENY"], "verdict": "DENY"},
    "error": {
        "reason_codes": ["REQUIRED_ANALYZER_FAILED:skillspector:TIMEOUT"],
        "verdict": "ERROR",
    },
    "review": {
        "reason_codes": ["CONFORMANCE_FIXTURE_ONLY"],
        "verdict": "REVIEW",
    },
}
_DETERMINISTIC_IMPLEMENTATION = {
    "admission_decision_digest": (
        "sha256:ca65af1d5e13b62718065fed0a933680f8336ca10217bde62e6c48f16ab1c683"
    ),
    "analyze_digest": (
        "sha256:f1721deaef0649e779950ebc1fff612a92a0f2757a2fb1149d642a6f15836949"
    ),
    "oci_worker_protocol_digest": (
        "sha256:0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b"
    ),
    "policy_digest": (
        "sha256:246a0f93c1c0e2ca803c8d1bda4e50a0bc4d3ab5855242532308396d6ad82d9b"
    ),
    "replay_runner_digest": (
        "sha256:43be1290771abc4c6664faa262a0c366e8078a3f8aa5143d05b747e01030b966"
    ),
}
_EMPTY_DIGEST = (
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
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
        _verify_openclaw_live_reload_slice(
            document,
            evidence_cas=evidence_cas,
            cron=False,
        )
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


def verify_openclaw_live_reload_cron_slice_evidence(
    document: Mapping[str, Any], *, evidence_cas: CAS
) -> None:
    """Verify one admitted update and three distinct live-reload consumers."""

    try:
        _verify_openclaw_live_reload_slice(
            document,
            evidence_cas=evidence_cas,
            cron=True,
        )
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
            f"invalid retained live-reload cron evidence: {exc}"
        ) from exc


def _verify_openclaw_live_reload_slice(
    document: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    cron: bool,
) -> None:
    (
        probe_digest,
        environment_digest,
        evidence_pair,
    ) = (
        (
            _LIVE_CRON_PROBE_DIGEST,
            _LIVE_CRON_ENV_DIGEST,
            _LIVE_CRON_EVIDENCE_PAIR,
        )
        if cron
        else (
            _LIVE_PROBE_DIGEST,
            _LIVE_ENV_DIGEST,
            _LIVE_EVIDENCE_PAIR,
        )
    )
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
        or {key: item["reason_codes"] for key, item in formal.items()}
        != _LIVE_RECEIPT_REASONS
    ):
        raise AdmissionEvidenceError("live-reload formal claim set changed")
    targeted = {"ADM-02/update", "ADM-02/reload"}
    for key, scenario in formal.items():
        expected = evidence_pair if key in targeted else []
        if scenario["evidence_digests"] != expected:
            raise AdmissionEvidenceError(
                f"{key} does not bind the exact live-reload evidence"
            )
    probe = _read_exact(evidence_cas, probe_digest, _LIVE_PROBE_SCHEMA)
    environment = _read_exact(
        evidence_cas,
        environment_digest,
        _LIVE_ENV_SCHEMA,
    )
    _verify_live_reload_bindings(
        document,
        probe,
        environment,
        cron=cron,
    )
    if cron:
        _verify_live_reload_cron_probe(probe)
    else:
        _verify_live_reload_probe(probe)
    _verify_live_reload_environment(
        probe,
        environment,
        cron=cron,
    )


def verify_openclaw_config_activation_slice_evidence(
    document: Mapping[str, Any], *, evidence_cas: CAS
) -> None:
    """Verify config activation, invalidation, and one missing-blob rebuild."""

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


def verify_openclaw_update_reload_coverage(
    document: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> None:
    """Derive partial update/reload coverage without granting authority."""

    try:
        if validate_admission_conformance(document) != "NOT_TESTED" or document[
            "decision"
        ] != {"status": "NOT_TESTED", "installer_work_eligible": False}:
            raise AdmissionEvidenceError(
                "update/reload coverage cannot grant installer authority"
            )
        formal = {
            f"{item['id']}/{scenario['id']}": scenario
            for item in document["properties"]
            for scenario in item["scenarios"]
        }
        if (
            set(formal) != set(_UPDATE_RELOAD_COVERAGE_REASONS)
            or any(item["status"] != "NOT_TESTED" for item in formal.values())
            or {key: item["reason_codes"] for key, item in formal.items()}
            != _UPDATE_RELOAD_COVERAGE_REASONS
        ):
            raise AdmissionEvidenceError(
                "update/reload coverage formal claim set changed"
            )
        targeted = {"ADM-02/update", "ADM-02/reload"}
        for key, scenario in formal.items():
            expected = [_UPDATE_RELOAD_COVERAGE_DIGEST] if key in targeted else []
            if scenario["evidence_digests"] != expected:
                raise AdmissionEvidenceError(
                    f"{key} does not bind the exact update/reload coverage"
                )
        coverage = _read_exact(
            evidence_cas,
            _UPDATE_RELOAD_COVERAGE_DIGEST,
            _UPDATE_RELOAD_COVERAGE_SCHEMA,
        )
        validate_openclaw_2026_7_1_route_inventory(
            route_inventory,
            runtime_candidates,
        )
        _verify_update_reload_coverage(
            document,
            coverage,
            evidence_cas=evidence_cas,
            route_inventory=route_inventory,
        )
    except AdmissionEvidenceError:
        raise
    except (
        AdmissionConformanceError,
        CASError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid retained update/reload coverage: {exc}"
        ) from exc


def _verify_update_reload_coverage(
    receipt: Mapping[str, Any],
    coverage: Mapping[str, Any],
    *,
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
            "source_receipt_digests",
        }
        or coverage["schema"] != _UPDATE_RELOAD_COVERAGE_SCHEMA
        or coverage["assurance"]
        != "SEMANTICALLY_VERIFIED_PARTIAL_COVERAGE_NOT_INSTALLER_AUTHORITY"
        or coverage["recorded_at"] != receipt["recorded_at"]
        or coverage["route_inventory_canonical_digest"]
        != canonical_digest(route_inventory)
        or coverage["route_inventory_canonical_digest"]
        != _UPDATE_RELOAD_INVENTORY_DIGEST
        or coverage["source_receipt_digests"] != _UPDATE_RELOAD_SOURCE_RECEIPTS
        or coverage["partial_observations"] != [_PARTIAL_UPDATE_OBSERVATION]
        or coverage["decision"]
        != {"status": "NOT_TESTED", "installer_work_eligible": False}
    ):
        raise AdmissionEvidenceError("update/reload coverage envelope changed")

    live_receipt = _read_exact(
        evidence_cas,
        _LIVE_CRON_RECEIPT_DIGEST,
        "aragorn/admission-conformance-result/v1",
    )
    config_receipt = _read_exact(
        evidence_cas,
        _CONFIG_RECEIPT_DIGEST,
        "aragorn/admission-conformance-result/v1",
    )
    verify_openclaw_live_reload_cron_slice_evidence(
        live_receipt,
        evidence_cas=evidence_cas,
    )
    verify_openclaw_config_activation_slice_evidence(
        config_receipt,
        evidence_cas=evidence_cas,
    )
    if _time(coverage["recorded_at"]) < max(
        _time(live_receipt["recorded_at"]),
        _time(config_receipt["recorded_at"]),
    ):
        raise AdmissionEvidenceError("coverage predates a source receipt")

    live_probe = _read_exact(
        evidence_cas,
        _LIVE_CRON_PROBE_DIGEST,
        _LIVE_PROBE_SCHEMA,
    )
    config_probe = _read_exact(
        evidence_cas,
        _CONFIG_PROBE_DIGEST,
        _CONFIG_PROBE_SCHEMA,
    )
    claims: dict[str, list[tuple[str, str]]] = {}
    for source_digest, probe, excluded_routes in (
        (
            _LIVE_CRON_RECEIPT_DIGEST,
            live_probe,
            {_PARTIAL_UPDATE_ROUTE},
        ),
        (_CONFIG_RECEIPT_DIGEST, config_probe, set()),
    ):
        for scenario in probe["scenarios"]:
            route_id = scenario["id"]
            status = scenario["status"]
            if status not in {"PASS", "FAIL"}:
                raise AdmissionEvidenceError("source route claim is inconclusive")
            if route_id in excluded_routes:
                if status != "PASS":
                    raise AdmissionEvidenceError(
                        "partial route observation is not a PASS"
                    )
                continue
            claims.setdefault(route_id, []).append((status, source_digest))

    route_ids = [
        f"{route['id']}/{path['id']}"
        for route in route_inventory["routes"]
        for path in route["paths"]
    ]
    route_shape = [
        (route["id"], len(route["paths"])) for route in route_inventory["routes"]
    ]
    if (
        route_shape != [("ADM-02/update", 9), ("ADM-02/reload", 12)]
        or len(route_ids) != 21
        or len(set(route_ids)) != len(route_ids)
    ):
        raise AdmissionEvidenceError("update/reload inventory cardinality changed")
    if not set(claims).issubset(route_ids):
        raise AdmissionEvidenceError("source proof names an uninventoried route")
    expected_routes = []
    for route_id in route_ids:
        route_claims = claims.get(route_id, [])
        expected_routes.append(
            {
                "id": route_id,
                "source_receipt_digests": sorted(
                    source for _, source in route_claims
                ),
                "status": _route_coverage_status(route_claims),
            }
        )
    if coverage["routes"] != expected_routes:
        raise AdmissionEvidenceError(
            "update/reload route coverage was not derived exactly"
        )

    if (
        live_receipt["bindings"]["runtime"] != config_receipt["bindings"]["runtime"]
        or live_receipt["bindings"]["aragorn"]
        != config_receipt["bindings"]["aragorn"]
        or live_receipt["bindings"]["environment"]["worker_digest"]
        != config_receipt["bindings"]["environment"]["worker_digest"]
    ):
        raise AdmissionEvidenceError("source coverage bindings are incompatible")
    source_bindings = [
        {
            "bindings": source["bindings"],
            "receipt_digest": digest,
        }
        for digest, source in (
            (_LIVE_CRON_RECEIPT_DIGEST, live_receipt),
            (_CONFIG_RECEIPT_DIGEST, config_receipt),
        )
    ]
    implementation_digest = (
        "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    )
    configuration = {
        "route_inventory_canonical_digest": _UPDATE_RELOAD_INVENTORY_DIGEST,
        "source_receipt_digests": _UPDATE_RELOAD_SOURCE_RECEIPTS,
    }
    source_environments = [
        item["bindings"]["environment"] for item in source_bindings
    ]
    expected_bindings = {
        "runtime": live_receipt["bindings"]["runtime"],
        "adapter": {
            "name": "openclaw-update-reload-route-coverage",
            "implementation_digest": implementation_digest,
            "configuration_digest": canonical_digest(configuration),
        },
        "environment": {
            "worker_digest": canonical_digest(
                [item["worker_digest"] for item in source_environments]
            ),
            "os_profile_digest": canonical_digest(source_environments),
        },
        "aragorn": {
            "implementation_digest": canonical_digest(
                {
                    "coverage_verifier_digest": implementation_digest,
                    "source_binding_set": source_bindings,
                }
            ),
            "policy_digest": live_receipt["bindings"]["aragorn"][
                "policy_digest"
            ],
        },
    }
    if receipt["bindings"] != expected_bindings:
        raise AdmissionEvidenceError("update/reload coverage bindings changed")


def _route_coverage_status(claims: list[tuple[str, str]]) -> str:
    if any(status == "FAIL" for status, _ in claims):
        return "FAIL"
    return "PASS" if claims else "NOT_TESTED"


def verify_openclaw_model_activation_evidence(
    document: Mapping[str, Any], *, evidence_cas: CAS
) -> None:
    """Verify exact fixture bytes reached the model transport through one read call."""

    try:
        if validate_admission_conformance(document) != "NOT_TESTED" or document[
            "decision"
        ] != {"status": "NOT_TESTED", "installer_work_eligible": False}:
            raise AdmissionEvidenceError(
                "model-activation slice cannot grant installer authority"
            )
        formal = {
            f"{item['id']}/{scenario['id']}": scenario
            for item in document["properties"]
            for scenario in item["scenarios"]
        }
        if (
            {key: item["status"] for key, item in formal.items()}
            != _MODEL_ACTIVATION_STATUSES
            or {
                key: item["reason_codes"]
                for key, item in formal.items()
                if item["status"] == "NOT_TESTED"
            }
            != _MODEL_ACTIVATION_REASONS
        ):
            raise AdmissionEvidenceError("model-activation formal claim set changed")
        for key, scenario in formal.items():
            expected = (
                _MODEL_ACTIVATION_EVIDENCE_SET
                if key == _MODEL_ACTIVATION_SCENARIO
                else []
            )
            if scenario["evidence_digests"] != expected:
                raise AdmissionEvidenceError(
                    f"{key} does not bind the exact model-activation evidence"
                )
        probe = _read_exact(
            evidence_cas,
            _MODEL_ACTIVATION_PROBE_DIGEST,
            _MODEL_ACTIVATION_PROBE_SCHEMA,
        )
        environment = _read_exact(
            evidence_cas,
            _MODEL_ACTIVATION_ENV_DIGEST,
            _MODEL_ACTIVATION_ENV_SCHEMA,
        )
        prior = _read_exact(
            evidence_cas,
            _CONFIG_PRIOR_ADMISSION_DIGEST,
            "aragorn/openclaw-contained-profile-probe-evidence/v1",
        )
        _verify_model_activation_bindings(document, probe, environment, prior)
        _verify_model_activation_probe(probe)
        _verify_model_activation_environment(probe, environment)
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
            f"invalid retained model-activation evidence: {exc}"
        ) from exc


def verify_openclaw_deterministic_replay_evidence(
    document: Mapping[str, Any], *, evidence_cas: CAS
) -> None:
    """Verify DET-01 only; fixed inputs do not transfer installer authority."""

    try:
        if validate_admission_conformance(document) != "NOT_TESTED" or document[
            "decision"
        ] != {"status": "NOT_TESTED", "installer_work_eligible": False}:
            raise AdmissionEvidenceError(
                "deterministic replay cannot grant installer authority"
            )
        formal = {
            f"{item['id']}/{scenario['id']}": scenario
            for item in document["properties"]
            for scenario in item["scenarios"]
        }
        if (
            {key: item["status"] for key, item in formal.items()}
            != _DETERMINISTIC_STATUSES
            or {
                key: item["reason_codes"]
                for key, item in formal.items()
                if item["status"] == "NOT_TESTED"
            }
            != _DETERMINISTIC_REASONS
        ):
            raise AdmissionEvidenceError("deterministic replay claim set changed")
        for key, scenario in formal.items():
            expected = (
                _DETERMINISTIC_EVIDENCE_SET
                if key == _DETERMINISTIC_SCENARIO
                else []
            )
            if scenario["evidence_digests"] != expected:
                raise AdmissionEvidenceError(
                    f"{key} does not bind the deterministic replay evidence"
                )
        vectors = _read_exact(
            evidence_cas,
            _DETERMINISTIC_VECTOR_DIGEST,
            _DETERMINISTIC_VECTOR_SCHEMA,
        )
        replay = _read_exact(
            evidence_cas,
            _DETERMINISTIC_REPLAY_DIGEST,
            _DETERMINISTIC_REPLAY_SCHEMA,
        )
        _verify_deterministic_replay(document, vectors, replay)
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
            f"invalid retained deterministic replay evidence: {exc}"
        ) from exc


def _verify_deterministic_replay(
    receipt: Mapping[str, Any],
    vector_set: Mapping[str, Any],
    replay: Mapping[str, Any],
) -> None:
    if (
        set(vector_set) != {"schema", "vectors"}
        or not isinstance(vector_set["vectors"], list)
        or len(vector_set["vectors"]) != len(_DETERMINISTIC_CASES)
        or set(replay)
        != {
            "adapter",
            "assurance",
            "cases",
            "environment",
            "limitations",
            "recorded_at",
            "schema",
            "vector_set_digest",
        }
        or replay["vector_set_digest"] != _DETERMINISTIC_VECTOR_DIGEST
        or receipt["recorded_at"] != replay["recorded_at"]
        or replay["assurance"]
        != "SELF_REPORTED_LOCAL_PROCESS_NOT_INDEPENDENTLY_ATTESTED"
        or replay["limitations"]
        != [
            "DECISION_ONLY_NOT_INSTALLER_AUTHORITY",
            "LOCAL_PROCESS_SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
            "SOURCE_ANALYZER_RESULTS_ARE_FIXED_RETAINED_VECTORS",
        ]
    ):
        raise AdmissionEvidenceError("deterministic replay envelope changed")

    adapter = replay["adapter"]
    configuration = {
        "case_ids": list(_DETERMINISTIC_CASES),
        "input_limit_bytes": 65_536,
        "module": "aragorn.admission_decision",
        "output_limit_bytes": 4_096,
        "seeds": list(_DETERMINISTIC_SEEDS),
        "timeout_seconds": 5,
        "vector_set_digest": _DETERMINISTIC_VECTOR_DIGEST,
    }
    if (
        set(adapter)
        != {
            "configuration",
            "configuration_digest",
            "implementation",
            "implementation_digest",
        }
        or adapter["configuration"] != configuration
        or adapter["configuration_digest"] != canonical_digest(configuration)
        or adapter["implementation"] != _DETERMINISTIC_IMPLEMENTATION
        or adapter["implementation_digest"]
        != canonical_digest(_DETERMINISTIC_IMPLEMENTATION)
    ):
        raise AdmissionEvidenceError("deterministic replay adapter changed")

    environment = replay["environment"]
    if (
        set(environment) != {"profile", "profile_digest"}
        or environment["profile_digest"] != canonical_digest(environment["profile"])
    ):
        raise AdmissionEvidenceError("deterministic replay environment changed")

    vectors = vector_set["vectors"]
    cases = replay["cases"]
    if not isinstance(cases, list) or len(cases) != len(vectors):
        raise AdmissionEvidenceError("deterministic replay case count changed")
    policies = []
    target_runtime = None
    for case_id, vector, retained in zip(
        _DETERMINISTIC_CASES,
        vectors,
        cases,
        strict=True,
    ):
        if (
            not isinstance(vector, Mapping)
            or set(vector) != {"expected", "request"}
            or vector["expected"] != _DETERMINISTIC_EXPECTED[case_id]
            or not isinstance(retained, Mapping)
            or set(retained) != {"case_id", "replays"}
        ):
            raise AdmissionEvidenceError("deterministic replay vector changed")
        request = vector["request"]
        if request["case_id"] != case_id or retained["case_id"] != case_id:
            raise AdmissionEvidenceError("deterministic replay case order changed")
        decision = evaluate_admission(request)
        if {
            "reason_codes": decision["reason_codes"],
            "verdict": decision["verdict"],
        } != vector["expected"]:
            raise AdmissionEvidenceError("deterministic replay expectation is false")
        raw_input = canonical_json(request) + b"\n"
        raw_output = canonical_json(decision) + b"\n"
        if len(raw_input) > 65_536 or len(raw_output) > 4_096:
            raise AdmissionEvidenceError("deterministic replay I/O limit changed")
        replays = retained["replays"]
        if (
            not isinstance(replays, list)
            or len(replays) != len(_DETERMINISTIC_SEEDS)
            or [item["seed"] for item in replays] != list(_DETERMINISTIC_SEEDS)
        ):
            raise AdmissionEvidenceError("deterministic replay seed set changed")
        for item in replays:
            if (
                set(item)
                != {
                    "exit_code",
                    "seed",
                    "stdin_digest",
                    "stderr_digest",
                    "stdout_digest",
                }
                or item["exit_code"] != 0
                or item["stdin_digest"] != _line_digest(request)
                or item["stdout_digest"] != _line_digest(decision)
                or item["stderr_digest"] != _EMPTY_DIGEST
            ):
                raise AdmissionEvidenceError(
                    "deterministic replay process record changed"
                )
        evidence = request["evidence"]
        if (
            evidence["source_evidence_digests"]
            != _MODEL_ACTIVATION_EVIDENCE_SET
            or evidence["source_receipt_digest"]
            != "sha256:ffae477eb5bc9be5568e506808a7e61e02c8e18e830475d7ac3e14da6a64f919"
        ):
            raise AdmissionEvidenceError("deterministic replay source binding changed")
        if target_runtime is None:
            target_runtime = request["target_runtime"]
        elif request["target_runtime"] != target_runtime:
            raise AdmissionEvidenceError("deterministic target runtime differs")
        policies.append(request["policy"])

    runtime = target_runtime["runtime"]
    expected_runtime = {
        key: runtime[key]
        for key in (
            "commit",
            "name",
            "repository_url",
            "source_tree_digest",
            "version",
        )
    }
    aragorn_implementation = {
        key: _DETERMINISTIC_IMPLEMENTATION[key]
        for key in (
            "admission_decision_digest",
            "analyze_digest",
            "oci_worker_protocol_digest",
            "policy_digest",
        )
    }
    if receipt["bindings"] != {
        "runtime": expected_runtime,
        "adapter": {
            "name": "openclaw-contained-deterministic-authority-replay",
            "implementation_digest": adapter["implementation_digest"],
            "configuration_digest": adapter["configuration_digest"],
        },
        "environment": {
            "worker_digest": environment["profile"]["executable_digest"],
            "os_profile_digest": environment["profile_digest"],
        },
        "aragorn": {
            "implementation_digest": canonical_digest(aragorn_implementation),
            "policy_digest": canonical_digest(policies),
        },
    }:
        raise AdmissionEvidenceError("deterministic replay receipt bindings changed")


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
    *,
    cron: bool,
) -> None:
    adapter_name = (
        "openclaw-contained-live-reload-cron-slice"
        if cron
        else "openclaw-contained-live-reload-slice"
    )
    implementation_digest = (
        _LIVE_CRON_IMPLEMENTATION_DIGEST
        if cron
        else _LIVE_IMPLEMENTATION_DIGEST
    )
    os_profile_digest = (
        _LIVE_CRON_OS_PROFILE_DIGEST if cron else _LIVE_OS_PROFILE_DIGEST
    )
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
            "name": adapter_name,
            "implementation_digest": implementation_digest,
            "configuration_digest": _LIVE_CONFIG_DIGEST,
        },
        "environment": {
            "worker_digest": _OPENCLAW_PLATFORM_MANIFEST,
            "os_profile_digest": os_profile_digest,
        },
        "aragorn": _ARAGORN_BINDING,
    }:
        raise AdmissionEvidenceError("live-reload receipt bindings changed")
    adapter = probe["adapter"]
    if (
        adapter["configuration_digest"]
        != canonical_digest(adapter["configuration"])
        or adapter["configuration_digest"] != _LIVE_CONFIG_DIGEST
        or adapter["implementation_digest"] != implementation_digest
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


def _verify_live_reload_cron_probe(  # noqa: PLR0915
    probe: Mapping[str, Any],
) -> None:
    expected_limitations = [
        "ONLY_LOCAL_DIRECTORY_GLOBAL_FORCE_REPLACEMENT_EXECUTED",
        "ONLY_FILESYSTEM_WATCH_EXISTING_CHAT_SESSION_SNAPSHOT_EXECUTED",
        "ONLY_TWO_FORCED_ISOLATED_CRON_RESCANS_EXECUTED",
        "CRON_TURNS_STOPPED_AT_MODEL_RESOLUTION_WITHOUT_PROVIDER_EXECUTION",
        "NORMAL_TURNS_INTENTIONALLY_FAIL_WITHOUT_PROVIDER_CREDENTIALS",
        "OTHER_UPDATE_RELOAD_PATHS_REMAIN_NOT_TESTED",
        "CONTAINED_DOCKER_ENVIRONMENT_NOT_INDEPENDENTLY_ATTESTED",
    ]
    scenarios = probe["scenarios"]
    if (
        probe["limitations"] != expected_limitations
        or [(item["id"], item["status"]) for item in scenarios]
        != [
            ("ADM-02/update/archive-source-force-replacement", "PASS"),
            ("ADM-02/reload/filesystem-watch-invalidation", "PASS"),
            ("ADM-02/reload/chat-session-snapshot-consumer", "PASS"),
            ("ADM-02/reload/cron-rescan", "PASS"),
        ]
    ):
        raise AdmissionEvidenceError("live-reload cron claim boundary changed")

    carried = {
        **probe,
        "limitations": [
            "ONLY_LOCAL_DIRECTORY_GLOBAL_FORCE_REPLACEMENT_EXECUTED",
            "ONLY_FILESYSTEM_WATCH_EXISTING_CHAT_SESSION_SNAPSHOT_EXECUTED",
            "NORMAL_TURNS_INTENTIONALLY_FAIL_WITHOUT_PROVIDER_CREDENTIALS",
            "OTHER_UPDATE_RELOAD_PATHS_REMAIN_NOT_TESTED",
            "CONTAINED_DOCKER_ENVIRONMENT_NOT_INDEPENDENTLY_ATTESTED",
        ],
        "scenarios": scenarios[:3],
    }
    _verify_live_reload_probe(carried)

    evidence = scenarios[3]["evidence"]
    job = evidence["job"]
    cleanup = evidence["cleanup"]
    run_before = evidence["run_before"]
    run_after = evidence["run_after"]
    snapshot_before = evidence["snapshot_before"]
    snapshot_after = evidence["snapshot_after"]
    job_id = job["response"]["id"]
    uuid4 = (
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
        r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    )
    if re.fullmatch(uuid4, job_id) is None:
        raise AdmissionEvidenceError("live-reload cron job identity changed")

    job_params = {
        "agentId": "main",
        "delivery": {"mode": "none"},
        "enabled": True,
        "name": "Aragorn isolated cron rescan probe",
        "payload": {
            "kind": "agentTurn",
            "message": "Inert isolated cron skill rescan probe.",
            "timeoutSeconds": 5,
        },
        "schedule": {"everyMs": 86_400_000, "kind": "every"},
        "sessionTarget": "isolated",
        "wakeMode": "now",
    }
    created_at_ms = job["response"]["createdAtMs"]
    if type(created_at_ms) is not int:  # noqa: E721
        raise AdmissionEvidenceError("live-reload cron creation time changed")
    rpc_prefix = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
    ]

    def rpc_argv(method: str, params: Mapping[str, Any]) -> list[str]:
        return rpc_prefix + [
            method,
            "--json",
            "--timeout",
            "5000",
            "--params",
            json.dumps(params, separators=(",", ":"), sort_keys=True),
        ]

    _verify_successful_config_command(
        job["command"],
        rpc_argv("cron.add", job_params),
    )
    if (
        job["params"] != job_params
        or job["response"]
        != {
            "agentId": "main",
            "createdAtMs": created_at_ms,
            "delivery": {"mode": "none"},
            "enabled": True,
            "id": job_id,
            "name": "Aragorn isolated cron rescan probe",
            "nextRunAtMs": created_at_ms + 86_400_000,
            "payload": job_params["payload"],
            "schedule": {
                "anchorMs": created_at_ms,
                "everyMs": 86_400_000,
                "kind": "every",
            },
            "sessionTarget": "isolated",
            "state": {"nextRunAtMs": created_at_ms + 86_400_000},
            "updatedAtMs": created_at_ms,
            "wakeMode": "now",
        }
        or not (
            _epoch_milliseconds(job["command"]["started_at"])
            <= created_at_ms
            <= _epoch_milliseconds(job["command"]["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("live-reload cron job creation changed")

    expected_snapshots = (
        (
            snapshot_before,
            {"allowed": False, "blocked": False, "seed": True},
            698,
            "sha256:"
            "df7b81a0879f2db0f9c81c0866aa1e229064d700fbb54758816c883c4f6eaca8",
        ),
        (
            snapshot_after,
            {"allowed": True, "blocked": False, "seed": False},
            716,
            "sha256:"
            "911e21e4c6ae9f26737475402a2f709675a0c9d47d26e862272c31ec77d4c75f",
        ),
    )
    for snapshot, markers, prompt_bytes, prompt_digest in expected_snapshots:
        lifecycle = snapshot["lifecycle_revision"]
        updated_at = snapshot["updated_at"]
        version = snapshot["version"]
        if (
            re.fullmatch(uuid4, lifecycle) is None
            or type(updated_at) is not int  # noqa: E721
            or type(version) is not int  # noqa: E721
            or snapshot
            != {
                "label": "Cron: Aragorn isolated cron rescan probe",
                "lifecycle_revision": lifecycle,
                "markers": markers,
                "model": "gpt-5.5",
                "model_provider": "openai",
                "prompt_bytes": prompt_bytes,
                "prompt_digest": prompt_digest,
                "prompt_storage": "promptRef",
                "session_key": f"agent:main:cron:{job_id}",
                "skill_filter": ["aragorn-admitted"],
                "skill_names": ["aragorn-admitted"],
                "system_sent": True,
                "updated_at": updated_at,
                "version": version,
            }
        ):
            raise AdmissionEvidenceError("live-reload cron snapshot changed")

    def verify_run(
        run: Mapping[str, Any],
        *,
        attempt: int,
        snapshot: Mapping[str, Any],
        previous_results: list[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        result = run["result"]
        run_id = result["runId"]
        session_id = result["sessionId"]
        match = re.fullmatch(
            rf"manual:{re.escape(job_id)}:([0-9]+):{attempt}",
            run_id,
        )
        if (
            match is None
            or re.fullmatch(uuid4, session_id) is None
            or any(
                type(result[key]) is not int  # noqa: E721
                for key in (
                    "durationMs",
                    "nextRunAtMs",
                    "runAtMs",
                    "ts",
                )
            )
            or result["durationMs"] < 0
            or result["nextRunAtMs"] <= result["ts"]
        ):
            raise AdmissionEvidenceError("live-reload cron run identity changed")
        diagnostic_ts = result["diagnostics"]["entries"][0]["ts"]
        if type(diagnostic_ts) is not int:  # noqa: E721
            raise AdmissionEvidenceError("live-reload cron diagnostic time changed")
        expected_result = {
            "action": "finished",
            "deliveryStatus": "not-requested",
            "diagnostics": {
                "entries": [
                    {
                        "message": "Unknown model: openai/gpt-5.5",
                        "severity": "error",
                        "source": "agent-run",
                        "ts": diagnostic_ts,
                    }
                ],
                "summary": "Unknown model: openai/gpt-5.5",
            },
            "durationMs": result["durationMs"],
            "error": "FailoverError: Unknown model: openai/gpt-5.5",
            "errorReason": "model_not_found",
            "jobId": job_id,
            "jobName": "Aragorn isolated cron rescan probe",
            "model": "gpt-5.5",
            "nextRunAtMs": result["nextRunAtMs"],
            "provider": "openai",
            "runAtMs": result["runAtMs"],
            "runId": run_id,
            "sessionId": session_id,
            "sessionKey": (
                f"agent:main:cron:{job_id}:run:{session_id}"
            ),
            "status": "error",
            "ts": result["ts"],
        }
        run_params = {"id": job_id, "mode": "force"}
        history_params = {"id": job_id, "limit": 10}
        _verify_successful_config_command(
            run["run"]["command"],
            rpc_argv("cron.run", run_params),
        )
        _verify_successful_config_command(
            run["history"]["command"],
            rpc_argv("cron.runs", history_params),
        )
        expected_history_entries = [expected_result, *previous_results]
        if (
            result != expected_result
            or run["run"]["params"] != run_params
            or run["run"]["response"]
            != {"enqueued": True, "ok": True, "runId": run_id}
            or run["history"]["params"] != history_params
            or run["history"]["response"]
            != {
                "entries": expected_history_entries,
                "hasMore": False,
                "limit": 10,
                "nextOffset": None,
                "offset": 0,
                "total": len(expected_history_entries),
            }
            or not 1 <= run["poll_count"] <= _LIVE_CRON_POLL_LIMIT
        ):
            raise AdmissionEvidenceError("live-reload cron run result changed")
        if not (
            _epoch_milliseconds(run["run"]["command"]["started_at"])
            <= int(match.group(1))
            <= result["runAtMs"]
            <= snapshot["updated_at"]
            <= diagnostic_ts
            <= result["ts"]
            <= _epoch_milliseconds(run["history"]["command"]["started_at"])
            <= _epoch_milliseconds(run["history"]["command"]["completed_at"])
        ) or (
            _time(run["run"]["command"]["completed_at"])
            > _time(run["history"]["command"]["started_at"])
        ):
            raise AdmissionEvidenceError(
                "live-reload cron run timing is not causal"
            )
        return expected_result

    before_result = verify_run(
        run_before,
        attempt=1,
        snapshot=snapshot_before,
        previous_results=[],
    )
    after_result = verify_run(
        run_after,
        attempt=2,
        snapshot=snapshot_after,
        previous_results=[before_result],
    )
    chat_before = scenarios[1]["evidence"]["snapshot_before"]
    chat_after = scenarios[1]["evidence"]["snapshot_after"]
    if (
        snapshot_before["prompt_digest"] != chat_before["prompt_digest"]
        or snapshot_before["version"] != chat_before["version"]
        or snapshot_after["prompt_digest"] != chat_after["prompt_digest"]
        or snapshot_after["version"] != chat_after["version"]
        or snapshot_before["version"] >= snapshot_after["version"]
        or snapshot_before["lifecycle_revision"]
        == snapshot_after["lifecycle_revision"]
        or before_result["runId"] == after_result["runId"]
        or before_result["sessionId"] == after_result["sessionId"]
    ):
        raise AdmissionEvidenceError("live-reload cron transition changed")

    cleanup_params = {"id": job_id}
    _verify_successful_config_command(
        cleanup["command"],
        rpc_argv("cron.remove", cleanup_params),
    )
    if (
        cleanup["params"] != cleanup_params
        or cleanup["response"] != {"ok": True, "removed": True}
    ):
        raise AdmissionEvidenceError("live-reload cron cleanup changed")

    blocked_command = scenarios[0]["evidence"]["blocked_command"]
    reload_wait = scenarios[2]["evidence"]["reload_turns"][-1]["wait"]["command"]
    if not (
        _time(job["command"]["completed_at"])
        <= _time(run_before["run"]["command"]["started_at"])
        and _time(run_before["history"]["command"]["completed_at"])
        <= _time(blocked_command["started_at"])
        and _time(reload_wait["completed_at"])
        <= _time(run_after["run"]["command"]["started_at"])
        and _time(run_after["history"]["command"]["completed_at"])
        <= _time(cleanup["command"]["started_at"])
        <= _time(cleanup["command"]["completed_at"])
        <= _time(probe["recorded_at"])
    ):
        raise AdmissionEvidenceError(
            "live-reload cron transition timing is not causal"
        )


def _verify_live_reload_environment(
    probe: Mapping[str, Any],
    environment: Mapping[str, Any],
    *,
    cron: bool = False,
) -> None:
    probe_digest = _LIVE_CRON_PROBE_DIGEST if cron else _LIVE_PROBE_DIGEST
    os_profile_digest = (
        _LIVE_CRON_OS_PROFILE_DIGEST if cron else _LIVE_OS_PROFILE_DIGEST
    )
    container_name = (
        "aragorn-openclaw-contained-live-reload-v2"
        if cron
        else "aragorn-openclaw-contained-live-reload-v1"
    )
    probe_volume = (
        "aragorn-openclaw-2026-7-1-contained-live-reload-probe-v2"
        if cron
        else "aragorn-openclaw-2026-7-1-contained-live-reload-probe-v1"
    )
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
    target_command = ["/usr/local/bin/node", "/probe/live-reload-probe.mjs"]
    execution_command = (
        target_command
        if cron
        else [
            "/bin/sh",
            "-c",
            "/usr/local/bin/node /probe/live-reload-probe.mjs > "
            "/tmp/live-reload-evidence.json; code=$?; "
            'printf "%s\\n" "$code" > /tmp/live-reload-exit-code; '
            'exit "$code"',
        ]
    )
    if (
        environment["recorded_at"] != probe["recorded_at"]
        or image != expected_image
        or container["command"] != startup
        or container["name"] != container_name
        or container["working_dir"] != "/profile/workspace"
        or execution["command"] != execution_command
        or execution["exit_code"] != 0
        or execution["mode"]
        != (
            "docker-exec-stdout-capture"
            if cron
            else "docker-exec-shell-capture"
        )
        or execution["recorded_at"] != probe["recorded_at"]
        or execution["target_command"] != target_command
        or execution["stdout"]
        != {
            "bytes": len(_canonical_bytes(probe)) + 1,
            "digest": probe_digest,
        }
        or execution["user"] != "1000:1000"
        or state["status"] != "exited"
        or state["exit_code"] != 0
        or state["running"]
        or state["paused"]
        or state["restarting"]
        or state["oom_killed"]
        or state["dead"]
        or state["error"] != ""
        or (
            state.get("restart_count") != 0
            if cron
            else "restart_count" in state
        )
    ):
        raise AdmissionEvidenceError("live-reload container execution changed")
    expected_mounts = [
        {
            "destination": "/probe",
            "read_only": True,
            "source": probe_volume,
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
    if cron:
        controls["restart_policy"] = {
            "maximum_retry_count": 0,
            "name": "no",
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
        or environment["os_profile_digest"] != os_profile_digest
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

    _verify_prior_exact_admission(prior)


def _verify_prior_exact_admission(prior: Mapping[str, Any]) -> None:
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
        or exact["evidence"]["effective_skills"]
        != [
            {
                "blockedByAgentFilter": False,
                "blockedByAllowlist": False,
                "commandVisible": True,
                "eligible": True,
                "modelVisible": True,
                "name": "aragorn-admitted",
                "source": "openclaw-managed",
            }
        ]
    ):
        raise AdmissionEvidenceError("prior exact-admission lineage changed")


def _verify_model_activation_bindings(
    receipt: Mapping[str, Any],
    probe: Mapping[str, Any],
    environment: Mapping[str, Any],
    prior: Mapping[str, Any],
) -> None:
    if (
        receipt["recorded_at"] != probe["recorded_at"]
        or environment["recorded_at"] != probe["recorded_at"]
    ):
        raise AdmissionEvidenceError("model-activation evidence timestamps differ")
    if receipt["bindings"] != {
        "runtime": {
            "name": "openclaw-contained",
            "version": "2026.7.1",
            "repository_url": "https://github.com/openclaw/openclaw",
            "commit": _OPENCLAW_COMMIT,
            "source_tree_digest": _OPENCLAW_RUNTIME_TREE,
        },
        "adapter": {
            "name": "openclaw-contained-model-activation-slice",
            "implementation_digest": _MODEL_ACTIVATION_IMPLEMENTATION_DIGEST,
            "configuration_digest": _MODEL_ACTIVATION_CONFIG_DIGEST,
        },
        "environment": {
            "worker_digest": _OPENCLAW_PLATFORM_MANIFEST,
            "os_profile_digest": _MODEL_ACTIVATION_OS_PROFILE_DIGEST,
        },
        "aragorn": _ARAGORN_BINDING,
    }:
        raise AdmissionEvidenceError("model-activation receipt bindings changed")

    adapter = probe["adapter"]
    config = adapter["configuration"]
    provider = config["models"]["providers"]["aragorn-mock"]
    if (
        adapter["configuration_digest"] != canonical_digest(config)
        or adapter["configuration_digest"] != _MODEL_ACTIVATION_CONFIG_DIGEST
        or adapter["implementation_digest"]
        != _MODEL_ACTIVATION_IMPLEMENTATION_DIGEST
        or set(config) != {"agents", "models", "plugins", "skills"}
        or config["agents"]
        != {
            "defaults": {
                "model": {"primary": "aragorn-mock/fixture-model"},
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
        }
        or config["models"]["mode"] != "replace"
        or set(config["models"]["providers"]) != {"aragorn-mock"}
        or provider["api"] != "openai-completions"
        or provider["apiKey"] != "aragorn-mock-local"
        or provider["baseUrl"] != "http://127.0.0.1:18080/v1"
        or provider["localService"]
        != {
            "args": ["/probe/model-activation-probe.mjs", "provider"],
            "command": "/usr/local/bin/node",
            "healthUrl": "http://127.0.0.1:18080/v1/models",
            "idleStopMs": 0,
            "readyTimeoutMs": 5000,
        }
        or [item["id"] for item in provider["models"]] != ["fixture-model"]
        or config["plugins"] != {"enabled": False}
        or config["skills"]
        != {
            "load": {
                "allowSymlinkTargets": [],
                "extraDirs": [],
                "watch": False,
            }
        }
    ):
        raise AdmissionEvidenceError("model-activation adapter binding changed")
    _verify_prior_exact_admission(prior)
    if probe["runtime"]["runtime_tree"]["tree_digest"] != prior["runtime"][
        "runtime_tree"
    ]["tree_digest"]:
        raise AdmissionEvidenceError("model-activation runtime lineage changed")


def _parse_model_request(record: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = record["body_raw"]
    if not isinstance(raw, str):
        raise AdmissionEvidenceError("model request body is not text")
    raw_bytes = raw.encode("utf-8")
    try:
        body = json.loads(
            raw,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError("model request body is invalid JSON") from exc
    if (
        record["body_bytes"] != len(raw_bytes)
        or record["body_digest"]
        != "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        or body != record["body"]
        or record["response_digest"]
        != "sha256:"
        + hashlib.sha256(_canonical_bytes(record["response"])).hexdigest()
    ):
        raise AdmissionEvidenceError("model request content binding changed")
    return body


def _model_request_prompt(body: Mapping[str, Any]) -> str:
    system = [
        item["content"]
        for item in body["messages"]
        if item["role"] == "system" and isinstance(item.get("content"), str)
    ]
    if len(system) != 1:
        raise AdmissionEvidenceError("model request system prompt changed")
    return system[0]


def _verify_model_activation_probe(probe: Mapping[str, Any]) -> None:  # noqa: PLR0915
    limitations = [
        "CONFORMANCE_FIXTURE_ADMISSION_NOT_PRODUCTION_ALLOW_LINEAGE",
        "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_NOT_EXTERNAL_MODEL_PROOF",
        "DET_01_AND_REMAINING_ADM_02_ROUTES_NOT_TESTED",
        "HOST_ROOT_AND_DOCKER_CONTROL_PLANE_NOT_INDEPENDENTLY_ATTESTED",
    ]
    scenario = probe["scenario"]
    if (
        probe["decision"]
        != {"installer_work_eligible": False, "status": "NOT_TESTED"}
        or probe["limitations"] != limitations
        or scenario["id"] != _MODEL_ACTIVATION_SCENARIO
        or scenario["status"] != "PASS"
    ):
        raise AdmissionEvidenceError("model-activation claim boundary changed")

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
        {key: runtime[key] for key in ("commit", "name", "version")}
        != {
            "commit": _OPENCLAW_COMMIT,
            "name": "openclaw-contained",
            "version": "2026.7.1",
        }
        or runtime["runtime_tree"]
        != {
            "algorithm": "aragorn/runtime-tree/v1",
            "entry_count": 45856,
            "file_count": 45837,
            "symlink_count": 19,
            "total_bytes": 369317461,
            "tree_digest": _OPENCLAW_RUNTIME_TREE,
        }
        or version["stdout_bytes"] != _MODEL_ACTIVATION_VERSION_STDOUT_BYTES
        or version["stdout_digest"]
        != "sha256:9e98975ff3973bcd88f224e1820a177c3c881f7a46b51b7dc5ec5d050f72607f"
    ):
        raise AdmissionEvidenceError("model-activation runtime identity changed")

    gateway = probe["gateway"]
    _verify_successful_config_command(
        gateway["readiness_command"],
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
    process_before = gateway["process_before"]
    log_before = gateway["log_before"]
    log_after = gateway["log_after"]
    if (
        gateway["system_info"]
        != {
            "arch": "arm64",
            "node_version": "v24.16.0",
            "pid": 1,
            "platform": "linux",
            "port": 18789,
        }
        or process_before["cmdline"] != ["openclaw-gateway"]
        or process_before["pid"] != 1
        or not isinstance(process_before["start_time_ticks"], str)
        or not process_before["start_time_ticks"].isdigit()
        or gateway["process_after"] != process_before
        or log_before["ready_count"] != 1
        or log_after["ready_count"] != 1
        or log_before["restart_count"] != 0
        or log_after["restart_count"] != 0
        or log_before["path"] != log_after["path"]
        or log_after["bytes"] <= log_before["bytes"]
    ):
        raise AdmissionEvidenceError("model-activation gateway proof changed")

    evidence = scenario["evidence"]
    target = evidence["target_before"]
    if (
        evidence["target_after"] != target
        or len(target) != _MODEL_ACTIVATION_TARGET_ENTRY_COUNT
        or target[0]["mode"] != "555"
        or target[0]["path"] != "."
        or target[0]["realpath"]
        != "/profile/state/skills/aragorn-admitted"
        or target[0]["type"] != "directory"
        or not isinstance(target[0]["size"], int)
        or target[0]["size"] <= 0
        or target[1]
        != {
            "digest": _ADMITTED_DIGEST,
            "links": 1,
            "mode": "444",
            "path": "SKILL.md",
            "realpath": (
                "/profile/state/skills/aragorn-admitted/SKILL.md"
            ),
            "size": len(_ADMITTED_TEXT.encode()),
            "type": "file",
        }
        or evidence["write_guard"]["blocked"] is not True
        or evidence["write_guard"]["code"] not in {"EACCES", "EROFS"}
        or evidence["session_store_absent_before"] is not True
    ):
        raise AdmissionEvidenceError("model-activation target identity changed")

    provider = probe["provider"]
    records = provider["records"]
    if (
        provider["request_count"] != _MODEL_ACTIVATION_REQUEST_COUNT
        or provider["transport"] != "openai-completions"
        or len(records) != _MODEL_ACTIVATION_REQUEST_COUNT
    ):
        raise AdmissionEvidenceError("model-activation request count changed")
    bodies = []
    expected_authorization = (
        "sha256:3b689f38774efb8ff5de570c82f1755d"
        "579469ec18ddeef9c72e292c72bcfb87"
    )
    for sequence, record in enumerate(records, 1):
        if (
            record["sequence"] != sequence
            or record["method"] != "POST"
            or record["path"] != "/v1/chat/completions"
            or record["content_type"] != "application/json"
            or record["authorization_digest"] != expected_authorization
        ):
            raise AdmissionEvidenceError("model-activation request metadata changed")
        bodies.append(_parse_model_request(record))

    first, second = bodies
    common = {
        "max_tokens": 256,
        "model": "fixture-model",
        "stream": True,
        "tool_choice": "auto",
    }
    if (
        {key: first[key] for key in common} != common
        or {key: second[key] for key in common} != common
        or [item["role"] for item in first["messages"]] != ["system", "user"]
        or [item["role"] for item in second["messages"]]
        != ["system", "user", "assistant", "tool"]
        or second["messages"][:2] != first["messages"]
        or second["tools"] != first["tools"]
    ):
        raise AdmissionEvidenceError("model-activation request sequence changed")

    prompt = _model_request_prompt(first)
    start = prompt.rfind("<available_skills>")
    end = prompt.find("</available_skills>", start)
    skill_block = (
        prompt[start : end + len("</available_skills>")]
        if start >= 0 and end > start
        else ""
    )
    expected_skill_block = (
        "<available_skills>\n"
        "  <skill>\n"
        "    <name>aragorn-admitted</name>\n"
        "    <description>Inert contained-profile fixture.</description>\n"
        "    <location>/profile/state/skills/aragorn-admitted/SKILL.md</location>\n"
        "    <version>sha256:5a951f65ad92bc20</version>\n"
        "  </skill>\n"
        "</available_skills>"
    )
    read_tools = [
        item for item in first["tools"] if item["function"]["name"] == "read"
    ]
    if (
        skill_block != expected_skill_block
        or skill_block.count("<skill>") != 1
        or len(read_tools) != 1
        or read_tools[0]["function"]["parameters"]["required"] != ["path"]
        or read_tools[0]["function"]["parameters"]["properties"]["path"]["type"]
        != "string"
    ):
        raise AdmissionEvidenceError("model-visible skill contract changed")

    target_path = "/profile/state/skills/aragorn-admitted/SKILL.md"
    transport_call = {
        "content": None,
        "role": "assistant",
        "tool_calls": [
            {
                "function": {
                    "arguments": json.dumps(
                        {"path": target_path},
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    "name": "read",
                },
                "id": "callaragornread1",
                "type": "function",
            }
        ],
    }
    transport_result = {
        "content": _ADMITTED_TEXT,
        "role": "tool",
        "tool_call_id": "callaragornread1",
    }
    if (
        second["messages"][2] != transport_call
        or second["messages"][3] != transport_result
        or "sha256:"
        + hashlib.sha256(second["messages"][3]["content"].encode()).hexdigest()
        != _ADMITTED_DIGEST
    ):
        raise AdmissionEvidenceError("exact read-tool result changed")

    target_arguments = json.dumps(
        {"path": target_path},
        separators=(",", ":"),
        sort_keys=True,
    )
    expected_read_response = [
        {
            "choices": [
                {
                    "delta": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "function": {
                                    "arguments": target_arguments,
                                    "name": "read",
                                },
                                "id": "call_aragorn_read_1",
                                "index": 0,
                                "type": "function",
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                    "index": 0,
                }
            ],
            "created": 0,
            "id": "chatcmpl-aragorn-read-1",
            "model": "fixture-model",
            "object": "chat.completion.chunk",
        }
    ]
    expected_final_response = [
        {
            "choices": [
                {
                    "delta": {
                        "content": "ARAGORN_EXACT_ACTIVATION_OK",
                        "role": "assistant",
                    },
                    "finish_reason": None,
                    "index": 0,
                }
            ],
            "created": 0,
            "id": "chatcmpl-aragorn-final-1",
            "model": "fixture-model",
            "object": "chat.completion.chunk",
        },
        {
            "choices": [
                {"delta": {}, "finish_reason": "stop", "index": 0}
            ],
            "created": 0,
            "id": "chatcmpl-aragorn-final-1",
            "model": "fixture-model",
            "object": "chat.completion.chunk",
            "usage": {
                "completion_tokens": 1,
                "prompt_tokens": 1,
                "total_tokens": 2,
            },
        },
    ]
    if (
        records[0]["response"] != expected_read_response
        or records[1]["response"] != expected_final_response
    ):
        raise AdmissionEvidenceError("model-activation mock response changed")

    _verify_model_activation_turn(probe)
    send = evidence["turn"]["send"]["command"]
    wait = evidence["turn"]["wait"]["command"]
    history = evidence["history"]["command"]
    if not (
        _time(version["started_at"])
        <= _time(version["completed_at"])
        <= _time(gateway["readiness_command"]["started_at"])
        <= _time(gateway["readiness_command"]["completed_at"])
        <= _time(send["started_at"])
        <= _time(send["completed_at"])
        <= _time(records[0]["received_at"])
        <= _time(records[1]["received_at"])
        <= _time(wait["completed_at"])
        <= _time(history["started_at"])
        <= _time(history["completed_at"])
        <= _time(probe["recorded_at"])
    ):
        raise AdmissionEvidenceError("model-activation timing is not causal")


def _verify_model_activation_turn(probe: Mapping[str, Any]) -> None:
    evidence = probe["scenario"]["evidence"]
    turn = evidence["turn"]
    run_id = "aragorn-model-activation-v1"
    session_key = "agent:main:aragorn-model-activation-v1"
    message = (
        "Read the admitted Aragorn skill file, then return the fixed result."
    )
    prefix = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
    ]
    send_params = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": message,
        "sessionKey": session_key,
        "timeoutMs": 10000,
    }
    wait_params = {"runId": run_id, "timeoutMs": 15000}
    history_params = {"limit": 20, "sessionKey": session_key}
    _verify_successful_config_command(
        turn["send"]["command"],
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
        turn["wait"]["command"],
        prefix
        + [
            "agent.wait",
            "--json",
            "--timeout",
            "17000",
            "--params",
            json.dumps(wait_params, separators=(",", ":"), sort_keys=True),
        ],
    )
    _verify_successful_config_command(
        evidence["history"]["command"],
        prefix
        + [
            "chat.history",
            "--json",
            "--timeout",
            "5000",
            "--params",
            json.dumps(history_params, separators=(",", ":"), sort_keys=True),
        ],
    )
    if (
        turn["send"]["response"] != {"runId": run_id, "status": "started"}
        or turn["wait"]["response"]["runId"] != run_id
        or turn["wait"]["response"]["status"] != "ok"
        or not isinstance(turn["wait"]["response"]["endedAt"], int)
        or evidence["final_text"] != "ARAGORN_EXACT_ACTIVATION_OK"
    ):
        raise AdmissionEvidenceError("model-activation turn result changed")

    history = evidence["history"]["response"]
    messages = history["messages"]
    target_path = "/profile/state/skills/aragorn-admitted/SKILL.md"
    if (
        [item["role"] for item in messages]
        != ["user", "assistant", "toolResult", "assistant"]
        or messages[0]["content"] != message
        or messages[0]["idempotencyKey"] != f"{run_id}:user"
        or messages[1]["content"]
        != [
            {
                "arguments": {"path": target_path},
                "id": "call_aragorn_read_1",
                "name": "read",
                "partialArgs": json.dumps(
                    {"path": target_path},
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                "type": "toolCall",
            }
        ]
        or messages[1]["stopReason"] != "toolUse"
        or messages[2]["toolCallId"] != "call_aragorn_read_1"
        or messages[2]["toolName"] != "read"
        or messages[2]["isError"] is not False
        or messages[2]["content"]
        != [{"text": _ADMITTED_TEXT, "type": "text"}]
        or messages[3]["provider"] != "aragorn-mock"
        or messages[3]["model"] != "fixture-model"
        or messages[3]["stopReason"] != "stop"
        or messages[3]["content"]
        != [{"text": "ARAGORN_EXACT_ACTIVATION_OK", "type": "text"}]
        or history["sessionKey"] != session_key
        or history["sessionInfo"]["key"] != session_key
        or history["sessionInfo"]["status"] != "done"
        or history["sessionInfo"]["model"] != "fixture-model"
        or history["sessionInfo"]["modelProvider"] != "aragorn-mock"
        or history["sessionInfo"]["activeRunIds"] != []
    ):
        raise AdmissionEvidenceError("model-activation history changed")


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
                "sha256:0118f067ca56d23e8c9c8724565dc021"
                "7db140733490fcedb1352b37f6870cb3"
            ),
            "size": 1150,
        },
        True: {
            "digest": (
                "sha256:a553600acf2066a5e4c80a2f53199326"
                "be4d28b40f6d929f453f497882f8eb6b"
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
        "ONLY_ONE_MISSING_PROMPT_BLOB_REBUILD_EXECUTED",
        "SESSION_STORE_MTIME_CHANGED_WITH_IDENTICAL_BYTES_TO_FORCE_CACHE_MISS",
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
        or version["stdout_bytes"] != _MODEL_ACTIVATION_VERSION_STDOUT_BYTES
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
        ("ADM-02/reload/missing-prompt-blob-rebuild", "PASS"),
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

    blob_evidence = scenarios[2]["evidence"]
    blob_before = blob_evidence["blob_before"]
    blob_after = blob_evidence["blob_after"]
    rebuild_turn = blob_evidence["rebuild_turn"]
    prompt_hash = (
        "df7b81a0879f2db0f9c81c0866aa1e229064d700fbb54758816c883c4f6eaca8"
    )
    prompt_ref = {
        "algorithm": "sha256",
        "bytes": 698,
        "hash": prompt_hash,
        "version": 1,
    }
    blob_path = (
        "/profile/state/agents/main/sessions/skills-prompts/sha256/df/"
        f"{prompt_hash}.txt"
    )
    for blob in (blob_before, blob_after):
        mtime_ns = blob.get("mtime_ns")
        if (
            not isinstance(mtime_ns, str)
            or not mtime_ns.isdigit()
            or blob
            != {
                "bytes": 698,
                "digest": f"sha256:{prompt_hash}",
                "mode": "600",
                "mtime_ns": mtime_ns,
                "nlink": 1,
                "path": blob_path,
                "prompt_ref": prompt_ref,
            }
        ):
            raise AdmissionEvidenceError("prompt blob identity changed")

    invalidation = blob_evidence["invalidation"]
    store_before = invalidation["store_before"]
    store_after = invalidation["store_after_rewrite"]
    store_path = "/profile/state/agents/main/sessions/sessions.json"
    store_digest = (
        "sha256:c75291d09ffcc49a678d0a0e9bf6a64c"
        "d5ca163ceedd8c794b246af8c4945501"
    )
    for store in (store_before, store_after):
        mtime_ns = store.get("mtime_ns")
        if (
            not isinstance(mtime_ns, str)
            or not mtime_ns.isdigit()
            or store
            != {
                "bytes": 1255,
                "digest": store_digest,
                "mode": "600",
                "mtime_ns": mtime_ns,
                "nlink": 1,
                "path": store_path,
            }
        ):
            raise AdmissionEvidenceError("session-store identity changed")
    if (
        invalidation
        != {
            "blob_exists_after_unlink": False,
            "completed_at": invalidation["completed_at"],
            "started_at": invalidation["started_at"],
            "store_after_rewrite": store_after,
            "store_before": store_before,
        }
        or int(store_after["mtime_ns"]) <= int(store_before["mtime_ns"])
        or int(blob_after["mtime_ns"]) <= int(blob_before["mtime_ns"])
        or int(blob_after["mtime_ns"]) <= int(store_after["mtime_ns"])
        or _time(invalidation["started_at"]) > _time(invalidation["completed_at"])
    ):
        raise AdmissionEvidenceError("missing prompt blob invalidation changed")

    _verify_config_turn(rebuild_turn, "prompt-rebuild", 0)
    rebuilt_snapshot = blob_evidence["rebuilt_snapshot"]
    _verify_config_snapshot_state(rebuilt_snapshot, enabled=True)
    stable_snapshot = (
        "session_id",
        "version",
        "marker_present",
        "prompt_bytes",
        "prompt_digest",
        "prompt_storage",
        "skill_names",
    )
    before_blob_ms = int(blob_before["mtime_ns"]) // 1_000_000
    after_blob_ms = int(blob_after["mtime_ns"]) // 1_000_000
    before_store_ms = int(store_before["mtime_ns"]) // 1_000_000
    after_store_ms = int(store_after["mtime_ns"]) // 1_000_000
    invalidation_started_ms = _epoch_milliseconds(invalidation["started_at"])
    send_started_ms = _epoch_milliseconds(
        rebuild_turn["send"]["command"]["started_at"]
    )
    wait_ended_ms = rebuild_turn["wait"]["response"]["endedAt"]
    wait_completed_ms = _epoch_milliseconds(
        rebuild_turn["wait"]["command"]["completed_at"]
    )
    recorded_ms = _epoch_milliseconds(probe["recorded_at"])
    if (
        {key: rebuilt_snapshot[key] for key in stable_snapshot}
        != {key: enabled_snapshot[key] for key in stable_snapshot}
        or rebuilt_snapshot["started_at"] <= enabled_snapshot["ended_at"]
        or not (
            enabled_snapshot["ended_at"]
            <= before_store_ms
            <= invalidation_started_ms
            and enabled_snapshot["ended_at"]
            <= before_blob_ms
            <= invalidation_started_ms
            <= after_store_ms
            <= send_started_ms + 1
            and send_started_ms
            <= rebuilt_snapshot["started_at"]
            <= rebuilt_snapshot["ended_at"]
            <= after_blob_ms
            <= wait_ended_ms
            <= wait_completed_ms
            <= recorded_ms
        )
    ):
        raise AdmissionEvidenceError("rebuilt prompt snapshot lineage changed")

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
        <= _time(invalidation["started_at"])
        <= _time(invalidation["completed_at"])
        <= _time(rebuild_turn["send"]["command"]["started_at"])
        <= _time(rebuild_turn["wait"]["command"]["completed_at"])
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
        or container["name"] != "aragorn-openclaw-contained-config-activation-v2"
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
                "aragorn-openclaw-2026-7-1-contained-config-activation-probe-v2"
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


def _verify_model_activation_environment(
    probe: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> None:
    container = environment["container"]
    state = container["state"]
    execution = container["probe_exec"]
    image = container["image"]
    expected_image = {
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
    startup = [
        "/usr/local/bin/node",
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
    ]
    target_command = [
        "/usr/local/bin/node",
        "/probe/model-activation-probe.mjs",
    ]
    probe_raw = _canonical_bytes(probe) + b"\n"
    first_prompt = _model_request_prompt(probe["provider"]["records"][0]["body"])
    if (
        environment["recorded_at"] != probe["recorded_at"]
        or image != expected_image
        or container["command"] != startup
        or container["name"]
        != "aragorn-openclaw-contained-model-activation-v2"
        or container["working_dir"] != "/profile/workspace"
        or execution
        != {
            "command": target_command,
            "exit_code": 0,
            "mode": "docker-exec-output-volume-capture",
            "recorded_at": probe["recorded_at"],
            "stdout": {
                "bytes": len(probe_raw),
                "digest": _line_digest(probe),
            },
            "target_command": target_command,
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
        or f"host={container['id'][:12]}" not in first_prompt
    ):
        raise AdmissionEvidenceError(
            "model-activation container execution changed"
        )

    expected_mounts = [
        {
            "destination": "/output",
            "read_only": False,
            "source": (
                "aragorn-openclaw-2026-7-1-contained-"
                "model-activation-output-v1"
            ),
            "type": "volume",
        },
        {
            "destination": "/probe",
            "read_only": True,
            "source": (
                "aragorn-openclaw-2026-7-1-contained-"
                "model-activation-probe-v2"
            ),
            "type": "volume",
        },
        {
            "destination": "/profile/config",
            "read_only": True,
            "source": (
                "aragorn-openclaw-2026-7-1-contained-"
                "model-activation-config-v1"
            ),
            "type": "volume",
        },
        {
            "destination": "/profile/home/.agents",
            "read_only": True,
            "source": (
                "aragorn-openclaw-2026-7-1-contained-"
                "model-activation-guard-v1"
            ),
            "type": "volume",
        },
        {
            "destination": "/profile/state/plugin-skills",
            "read_only": True,
            "source": (
                "aragorn-openclaw-2026-7-1-contained-"
                "model-activation-guard-v1"
            ),
            "type": "volume",
        },
        {
            "destination": "/profile/state/skills",
            "read_only": True,
            "source": (
                "aragorn-openclaw-2026-7-1-contained-"
                "model-activation-admitted-v1"
            ),
            "type": "volume",
        },
        {
            "destination": "/profile/workspace/.agents",
            "read_only": True,
            "source": (
                "aragorn-openclaw-2026-7-1-contained-"
                "model-activation-guard-v1"
            ),
            "type": "volume",
        },
        {
            "destination": "/profile/workspace/skills",
            "read_only": True,
            "source": (
                "aragorn-openclaw-2026-7-1-contained-"
                "model-activation-guard-v1"
            ),
            "type": "volume",
        },
        {
            "destination": "/runtime",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-runtime-v2",
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
    writable = [
        item["destination"]
        for item in isolation["mounts"]
        if not item["read_only"]
    ]
    if (
        {key: isolation[key] for key in controls} != controls
        or isolation["environment"]
        != {
            "HOME": "/profile/home",
            "NODE_VERSION": "24.16.0",
            "OPENCLAW_CONFIG_PATH": "/profile/config/openclaw.json",
            "OPENCLAW_GATEWAY_TOKEN": (
                "aragorn-contained-model-activation-token-v1"
            ),
            "OPENCLAW_STATE_DIR": "/profile/state",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "YARN_VERSION": "1.22.22",
        }
        or len({item["destination"] for item in isolation["mounts"]})
        != len(expected_mounts)
        or writable != ["/output"]
        or "/profile/state/skills" in isolation["tmpfs"]
    ):
        raise AdmissionEvidenceError("model-activation isolation changed")

    docker = environment["docker"]
    server = docker["server"]
    os_profile = {
        "image": image,
        "isolation": isolation,
        "server": server,
    }
    if (
        environment["os_profile_digest"] != canonical_digest(os_profile)
        or environment["os_profile_digest"]
        != _MODEL_ACTIVATION_OS_PROFILE_DIGEST
        or docker["assurance"] != "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED"
        or docker["context"]
        != {
            "endpoint": "unix:///Users/yousi/.colima/default/docker.sock",
            "name": "colima",
            "skip_tls_verify": False,
            "tls_material_count": 0,
        }
        or {
            key: server[key]
            for key in (
                "architecture",
                "cgroup_driver",
                "cgroup_version",
                "default_runtime",
                "kernel_version",
                "operating_system",
                "os",
                "security_options",
                "version",
            )
        }
        != {
            "architecture": "aarch64",
            "cgroup_driver": "cgroupfs",
            "cgroup_version": "2",
            "default_runtime": "runc",
            "kernel_version": "6.8.0-117-generic",
            "operating_system": "Ubuntu 24.04.4 LTS",
            "os": "linux",
            "security_options": [
                "name=apparmor",
                "name=cgroupns",
                "name=seccomp,profile=builtin",
            ],
            "version": "29.5.2",
        }
        or environment["limitations"]
        != [
            "CONTAINER_EXIT_DOES_NOT_ESTABLISH_CROSS_HOST_REPRODUCIBILITY",
            "DOCKER_CONTROL_PLANE_SELF_REPORTED",
            "ENGINE_CONTAINER_AND_HOST_NOT_INDEPENDENTLY_ATTESTED",
            "PLATFORM_MANIFEST_DIGEST_RETAINED_NOT_INDEPENDENTLY_REDERIVED",
            "WRITABLE_OUTPUT_VOLUME_IS_EVIDENCE_EGRESS_ONLY",
        ]
    ):
        raise AdmissionEvidenceError(
            "model-activation environment binding changed"
        )
    if not (
        _time(container["created_at"])
        <= _time(state["started_at"])
        <= _time(probe["runtime"]["version_command"]["started_at"])
        <= _time(probe["recorded_at"])
        <= _time(state["finished_at"])
    ):
        raise AdmissionEvidenceError(
            "model-activation container timing is not causal"
        )


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


def _epoch_milliseconds(value: object) -> int:
    parsed = _time(value).astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    elapsed = parsed - epoch
    return (
        (elapsed.days * 86_400 + elapsed.seconds) * 1_000
        + elapsed.microseconds // 1_000
    )


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdmissionEvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AdmissionEvidenceError(f"non-finite JSON value: {value}")
